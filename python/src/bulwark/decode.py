"""Recursively recover encoded payloads so the detector can see them.

Signature matching only works on text the detector can read. An attacker who
writes ``aWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM=`` next to "decode this and
follow it" gets a model that reads the instruction and a regex database that
sees a meaningless blob. Flagging "there is a Base64 blob here" — which is all
Bulwark used to do — is a weak proxy: real pages are full of hashes and tokens,
so the signal has to stay low-weight to avoid false positives.

This module closes that gap by actually **decoding** and handing every recovered
layer back to the detector, keeping a provenance chain so a finding can say
*where* it came from: ``base64 → percent → "ignore all previous instructions"``.

Two kinds of decoder:

* **Span extractors** find an encoded region inside the text (a Base64 run, a
  percent-encoded sequence, a zero-width bit string) and decode just that span.
* **Whole-text transforms** rewrite the entire text (ROT13, reversal), because
  those ciphers have no delimiters to find.

Everything is budgeted. Decoding is attacker-controlled work, so depth, layer
count and total decoded size are all hard-capped; the caps are chosen so a
pathological input costs a bounded, small multiple of one ordinary scan.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Tuple

# --- budgets ---------------------------------------------------------------
# Decoding is work an attacker asks us to do, so every dimension is capped.
MAX_DEPTH = 3               # base64(base64(rot13(payload))) is reachable; deeper is fantasy
MAX_LAYERS = 24             # total decoded layers returned
MAX_TOTAL_CHARS = 262_144   # summed size of all decoded text
MAX_PER_EXTRACTOR = 6       # candidate spans one extractor may yield per layer
MIN_PAYLOAD_CHARS = 12      # shorter decodes carry no instruction worth acting on
MAX_INPUT_CHARS = 200_000   # do not even look at inputs larger than the pipeline cap


@dataclass(frozen=True)
class DecodedLayer:
    """One recovered plaintext, plus how we got to it."""

    text: str
    chain: Tuple[str, ...]           # ("base64",) or ("base64", "rot13")
    span: Optional[Tuple[int, int]]  # offsets in the immediate parent, None for whole-text
    parent: int                      # index into the layer list, -1 for the original input

    @property
    def label(self) -> str:
        return " → ".join(self.chain)


# --- plausibility ----------------------------------------------------------

_TEXTY_RE = re.compile(r"[A-Za-zÀ-ɏͰ-῿぀-鿿]")


def looks_like_text(s: str) -> bool:
    """Is this decode plausibly natural-language text rather than binary noise?

    Deliberately permissive: the cost of a false "yes" is one extra signature
    pass over a short string, while a false "no" silently drops an attack.
    """
    if len(s) < MIN_PAYLOAD_CHARS:
        return False
    printable = 0
    letters = 0
    for ch in s:
        cat = unicodedata.category(ch)
        if cat[0] in ("L", "N", "P", "Z", "S") or ch in "\n\r\t":
            printable += 1
        if cat[0] == "L":
            letters += 1
    n = len(s)
    return printable / n >= 0.85 and letters / n >= 0.25


# --- span extractors -------------------------------------------------------

# Contiguous runs, optionally wrapped at newlines (MIME style). The line-break
# group uses [ \t] and \n — disjoint character classes — so there is no
# alternation overlap for a backtracking engine to explode on.
_B64_RUN_RE = re.compile(r"[A-Za-z0-9+/]{24,}(?:[ \t]*\n[ \t]*[A-Za-z0-9+/]{4,})*={0,2}")
_B64URL_RUN_RE = re.compile(r"[A-Za-z0-9_-]{24,}={0,2}")
_HEX_RUN_RE = re.compile(r"(?:[0-9a-fA-F]{2}[\s:,-]?){12,}")
_PERCENT_RUN_RE = re.compile(r"(?:%[0-9a-fA-F]{2}){6,}")
_NUMERIC_ENTITY_RE = re.compile(r"&#(?:\d{1,7}|[xX][0-9a-fA-F]{1,6});")
_ESCAPE_RUN_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|\\[0-7]{3}){6,}")
_DECIMAL_RUN_RE = re.compile(r"(?:\d{2,3}[\s,;.]+){8,}\d{2,3}")
_SPACED_LETTERS_RE = re.compile(r"(?:[A-Za-z][ .\-_*|]{1,3}){8,}[A-Za-z]")
_MORSE_RE = re.compile(r"(?:[.\-]{1,6}[ /]+){6,}[.\-]{1,6}")
# Zero-width bits: U+200B/U+200C (or U+FEFF) used as 0/1. Runs are long by nature.
_ZW_BITS_RE = re.compile(r"[​‌‍﻿]{16,}")

_MORSE_TABLE = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f",
    "--.": "g", "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l",
    "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r",
    "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
    "-.--": "y", "--..": "z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}


def _b64_decode(blob: str, *, urlsafe: bool = False) -> Optional[str]:
    compact = "".join(blob.split())
    if len(compact) < 24:
        return None
    if urlsafe:
        compact = compact.replace("-", "+").replace("_", "/")
    padded = compact + "=" * (-len(compact) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _extract_base64(text: str) -> List[Tuple[Tuple[int, int], str, str]]:
    found: List[Tuple[Tuple[int, int], str, str]] = []
    for regex, name, urlsafe in ((_B64_RUN_RE, "base64", False), (_B64URL_RUN_RE, "base64url", True)):
        count = 0
        for m in regex.finditer(text):
            if count >= MAX_PER_EXTRACTOR:
                break
            blob = m.group(0)
            # The URL-safe alphabet is a superset match for standard Base64, so
            # only claim "base64url" when a URL-safe-only character is present.
            if urlsafe and "-" not in blob and "_" not in blob:
                continue
            decoded = _b64_decode(blob, urlsafe=urlsafe)
            if decoded and looks_like_text(decoded):
                found.append(((m.start(), m.end()), name, decoded))
                count += 1
    return found


def _extract_hex(text: str) -> List[Tuple[Tuple[int, int], str, str]]:
    found = []
    for m in _HEX_RUN_RE.finditer(text):
        if len(found) >= MAX_PER_EXTRACTOR:
            break
        digits = re.sub(r"[^0-9a-fA-F]", "", m.group(0))
        if len(digits) % 2:
            digits = digits[:-1]
        try:
            decoded = bytes.fromhex(digits).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if looks_like_text(decoded):
            found.append(((m.start(), m.end()), "hex", decoded))
    return found


def _extract_percent(text: str) -> List[Tuple[Tuple[int, int], str, str]]:
    from urllib.parse import unquote

    found = []
    for m in _PERCENT_RUN_RE.finditer(text):
        if len(found) >= MAX_PER_EXTRACTOR:
            break
        try:
            decoded = unquote(m.group(0), errors="strict")
        except UnicodeDecodeError:
            continue  # percent bytes that aren't UTF-8 text — not a payload
        if decoded != m.group(0) and looks_like_text(decoded):
            found.append(((m.start(), m.end()), "percent", decoded))
    return found


def _extract_entities(text: str) -> List[Tuple[Tuple[int, int], str, str]]:
    # Entities are scattered rather than contiguous, so unescape the whole text
    # once and treat the result as a single decoded layer. Gated on *numeric*
    # references: &amp; and friends are ordinary HTML, but spelling a word out
    # as &#105;&#103;&#110;… is only ever obfuscation.
    if len(_NUMERIC_ENTITY_RE.findall(text)) < 3:
        return []
    decoded = html.unescape(text)
    if decoded == text or not looks_like_text(decoded):
        return []
    return [((0, len(text)), "html_entities", decoded)]


def _extract_escapes(text: str) -> List[Tuple[Tuple[int, int], str, str]]:
    found = []
    for m in _ESCAPE_RUN_RE.finditer(text):
        if len(found) >= MAX_PER_EXTRACTOR:
            break
        try:
            decoded = m.group(0).encode("ascii").decode("unicode_escape")
        except (UnicodeDecodeError, UnicodeEncodeError):
            continue
        if looks_like_text(decoded):
            found.append(((m.start(), m.end()), "unicode_escape", decoded))
    return found


def _extract_decimal(text: str) -> List[Tuple[Tuple[int, int], str, str]]:
    found = []
    for m in _DECIMAL_RUN_RE.finditer(text):
        if len(found) >= MAX_PER_EXTRACTOR:
            break
        numbers = [int(n) for n in re.findall(r"\d{2,3}", m.group(0))]
        if not numbers or any(n > 126 or n < 32 for n in numbers):
            continue
        decoded = "".join(chr(n) for n in numbers)
        if looks_like_text(decoded):
            found.append(((m.start(), m.end()), "decimal_codes", decoded))
    return found


def _extract_spaced(text: str) -> List[Tuple[Tuple[int, int], str, str]]:
    found = []
    for m in _SPACED_LETTERS_RE.finditer(text):
        if len(found) >= MAX_PER_EXTRACTOR:
            break
        # A single separator joins letters within a word; a run of two or more
        # is the word break, so "i g n o r e  a l l" collapses to "ignore all".
        # Park the word breaks somewhere the letter-joining pass can't see them.
        decoded = re.sub(r"[ .\-_*|]{2,}", "\x00", m.group(0))
        decoded = re.sub(r"(?<=[A-Za-z])[ .\-_*|](?=[A-Za-z])", "", decoded)
        decoded = decoded.replace("\x00", " ")
        if looks_like_text(decoded):
            found.append(((m.start(), m.end()), "letter_spacing", decoded))
    return found


def _extract_morse(text: str) -> List[Tuple[Tuple[int, int], str, str]]:
    found = []
    for m in _MORSE_RE.finditer(text):
        if len(found) >= MAX_PER_EXTRACTOR:
            break
        letters = []
        for word in m.group(0).split("/"):
            for symbol in word.split():
                letters.append(_MORSE_TABLE.get(symbol, ""))
            letters.append(" ")
        decoded = "".join(letters).strip()
        if looks_like_text(decoded):
            found.append(((m.start(), m.end()), "morse", decoded))
    return found


def _extract_zero_width_bits(text: str) -> List[Tuple[Tuple[int, int], str, str]]:
    """Zero-width characters used as binary. Only meaningful on *raw* text —
    sanitization strips these, which is why unwrap() runs before it."""
    found = []
    for m in _ZW_BITS_RE.finditer(text):
        if len(found) >= MAX_PER_EXTRACTOR:
            break
        bits = "".join("0" if ch in "​﻿" else "1" for ch in m.group(0))
        usable = len(bits) - (len(bits) % 8)
        if usable < 24:
            continue
        try:
            decoded = bytes(
                int(bits[i:i + 8], 2) for i in range(0, usable, 8)
            ).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if looks_like_text(decoded):
            found.append(((m.start(), m.end()), "zero_width_bits", decoded))
    return found


_SPAN_EXTRACTORS: Sequence[Callable[[str], List[Tuple[Tuple[int, int], str, str]]]] = (
    _extract_base64,
    _extract_hex,
    _extract_percent,
    _extract_entities,
    _extract_escapes,
    _extract_decimal,
    _extract_spaced,
    _extract_morse,
    _extract_zero_width_bits,
)


# --- whole-text transforms -------------------------------------------------

_ROT13 = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


def rot13(text: str) -> str:
    return text.translate(_ROT13)


def reverse(text: str) -> str:
    return text[::-1]


# Whole-text ciphers have no delimiter to find, so they are simply tried.
_WHOLE_TRANSFORMS: Sequence[Tuple[str, Callable[[str], str]]] = (
    ("rot13", rot13),
    ("reversed", reverse),
)

# Function words that survive any topic. A ROT13'd or reversed English sentence
# scores near zero on these; its decoding scores high. Comparing the two is what
# keeps these transforms from emitting a useless second copy of every document.
_STOPWORDS = frozenset("""
the be to of and a in that have it for not on with as you do at this but his by
from they we say her she or an will my one all would there their what so up out
if about who get which go me when make can like time no just him know take people
into your some could them see other than then now look only come its over think
also back after use two how our work first well way even new want because any
these give day most us is are was were been has had please must should your you
""".split())
_WORD_RE = re.compile(r"[A-Za-z']+")


def _english_score(text: str) -> float:
    """Fraction of words that are common English function words, over the first
    400 words. Cheap, allocation-light, and good enough to tell a decoding from
    its ciphertext."""
    words = _WORD_RE.findall(text.lower())[:400]
    if len(words) < 4:
        return 0.0
    return sum(1 for w in words if w in _STOPWORDS) / len(words)


# --- the unwrapper ---------------------------------------------------------

def unwrap(
    text: str,
    *,
    max_depth: int = MAX_DEPTH,
    max_layers: int = MAX_LAYERS,
    max_total_chars: int = MAX_TOTAL_CHARS,
    whole_text_transforms: bool = True,
) -> List[DecodedLayer]:
    """Recover every plausible encoded payload in ``text``, recursively.

    Returns the decoded layers only — never the original. Order is
    breadth-first, so shallow (and usually more relevant) decodes come first.
    Deduplicated by decoded text so ``base64`` and ``base64url`` matching the
    same run don't both appear.
    """
    if not text or len(text) > MAX_INPUT_CHARS:
        return []

    layers: List[DecodedLayer] = []
    seen: set = {" ".join(text.split())}
    total_chars = 0

    # (text, parent index, chain, depth)
    frontier: List[Tuple[str, int, Tuple[str, ...], int]] = [(text, -1, (), 0)]

    while frontier and len(layers) < max_layers and total_chars < max_total_chars:
        current, parent, chain, depth = frontier.pop(0)
        if depth >= max_depth:
            continue

        candidates: List[Tuple[Optional[Tuple[int, int]], str, str]] = []
        for extractor in _SPAN_EXTRACTORS:
            candidates.extend(extractor(current))
        # Whole-text ciphers only at the top level: rot13(rot13(x)) == x, and
        # allowing them at depth turns the frontier into a treadmill. Keep a
        # transform only when it makes the text look MORE like English than it
        # already did — otherwise every ordinary document would emit two useless
        # gibberish layers for the detector to chew through.
        if whole_text_transforms and depth == 0:
            baseline = _english_score(current)
            for name, fn in _WHOLE_TRANSFORMS:
                transformed = fn(current)
                if transformed == current or not looks_like_text(transformed):
                    continue
                if _english_score(transformed) > max(baseline, 0.04):
                    candidates.append((None, name, transformed))

        for span, name, decoded in candidates:
            if len(layers) >= max_layers or total_chars >= max_total_chars:
                break
            key = " ".join(decoded.split())
            if not key or key in seen:
                continue
            seen.add(key)
            total_chars += len(decoded)
            layer = DecodedLayer(text=decoded, chain=chain + (name,), span=span, parent=parent)
            layers.append(layer)
            frontier.append((decoded, len(layers) - 1, layer.chain, depth + 1))

    return layers


def describe(layers: Sequence[DecodedLayer], limit: int = 5) -> str:
    """One-line human summary, e.g. ``base64 (1), base64 → rot13 (1)``."""
    if not layers:
        return ""
    counts: Dict[str, int] = {}
    for layer in layers:
        counts[layer.label] = counts.get(layer.label, 0) + 1
    parts = [f"{label} ({n})" for label, n in list(counts.items())[:limit]]
    if len(counts) > limit:
        parts.append(f"and {len(counts) - limit} more")
    return ", ".join(parts)
