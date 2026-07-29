"""Rampart — replace sensitive values with typed placeholders before the model sees them.

The rest of Bulwark stops a hostile page from steering your model. Rampart
handles the mirror-image risk: your model — or the provider behind it — seeing
data it never needed. A fetched page, an email body, a support ticket or a log
excerpt routinely carries a real person's email, card or national ID, and an API
key or private key besides. Rampart replaces each one with a typed, reversible
placeholder (``[EMAIL_1_7f3a]``) so the model reasons over structure rather than
secrets, and — when the model is remote — the raw value never leaves the machine.

This is the *deterministic* layer: regexes gated by checksum validators, zero
dependencies, no model to load. It matches structured identifiers exactly —
Luhn-valid cards, mod-97-valid IBANs, structurally-valid SSNs, validated IPv4
and IPv6, JWTs whose header really decodes to JSON. Names and street addresses
need a NER model and belong in the host application; this is the portable,
always-available floor beneath it.

Approach inspired by National Design Studio's Rampart (CC BY 4.0); this is an
original, dependency-free reimplementation of the deterministic detectors.

Placeholder nonces
------------------
Every placeholder carries a short random suffix drawn per redaction, and
:func:`rehydrate` restores only tokens bearing that redaction's nonce. Without
it there is a real exfiltration path: an attacker who knows the placeholder
format plants ``[EMAIL_1]`` in a page, the model echoes it, and a host that
rehydrates the reply substitutes a *real* address into text the attacker can
read. The nonce is unguessable, so a planted placeholder simply stays literal.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


class Entity(str, Enum):
    """A class of sensitive value. The value is the placeholder prefix."""

    EMAIL = "EMAIL"
    PHONE = "PHONE"
    CREDIT_CARD = "CREDIT_CARD"
    SSN = "SSN"
    IP_ADDRESS = "IP_ADDRESS"
    IBAN = "IBAN"
    MAC_ADDRESS = "MAC_ADDRESS"
    API_KEY = "API_KEY"
    JWT = "JWT"
    PRIVATE_KEY = "PRIVATE_KEY"
    CRYPTO_ADDRESS = "CRYPTO_ADDRESS"
    NATIONAL_ID = "NATIONAL_ID"


# Higher priority wins an overlap: a checksum-backed class beats a looser one on
# the same bytes, so a Luhn-valid 16-digit run is a card, not a phone number.
_PRIORITY: Dict[Entity, int] = {
    Entity.PRIVATE_KEY: 9,
    Entity.JWT: 7,
    Entity.API_KEY: 6,
    Entity.CREDIT_CARD: 5,
    Entity.IBAN: 5,
    Entity.CRYPTO_ADDRESS: 5,
    Entity.SSN: 4,
    Entity.EMAIL: 4,
    Entity.NATIONAL_ID: 4,
    Entity.MAC_ADDRESS: 3,
    Entity.IP_ADDRESS: 3,
    Entity.PHONE: 2,
}


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    entity: Entity
    value: str

    @property
    def priority(self) -> int:
        return _PRIORITY[self.entity]


@dataclass
class Redaction:
    """The result of a redaction pass."""

    text: str
    count: int
    summary: str                                   # "EMAIL×2, SSN×1" — labels and counts only
    map: Dict[str, str] = field(default_factory=dict)   # placeholder → original
    nonce: str = ""
    entities: Set[Entity] = field(default_factory=set)

    @property
    def redacted(self) -> bool:
        return self.count > 0


# --- validators (useful on their own) --------------------------------------

def luhn_valid(digits: str) -> bool:
    """Mod-10 checksum. Gates CREDIT_CARD so arbitrary digit runs don't match."""
    if not digits or not digits.isdigit():
        return False
    total = 0
    double = False
    for ch in reversed(digits):
        d = int(ch)
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double
    return total % 10 == 0


def valid_ssn(digits: str) -> bool:
    """US SSN structural rules: area not 000/666/900-999, group not 00, serial
    not 0000. Rejects the many nine-digit runs that are order numbers."""
    if len(digits) != 9 or not digits.isdigit():
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in ("000", "666") or int(area) >= 900:
        return False
    return group != "00" and serial != "0000"


def iban_valid(candidate: str) -> bool:
    """ISO 13616 mod-97 check. Without it, any ``XX00`` followed by alphanumerics
    matches — which is most product codes."""
    compact = re.sub(r"[\s-]", "", candidate).upper()
    if not 15 <= len(compact) <= 34 or not compact[:2].isalpha() or not compact[2:4].isdigit():
        return False
    rearranged = compact[4:] + compact[:4]
    total = 0
    for ch in rearranged:
        if ch.isdigit():
            total = (total * 10 + int(ch)) % 97
        elif ch.isalpha():
            total = (total * 100 + (ord(ch) - 55)) % 97
        else:
            return False
    return total == 1


def jwt_valid(candidate: str) -> bool:
    """Three base64url segments whose header decodes to JSON naming an algorithm."""
    import base64

    parts = candidate.split(".")
    if len(parts) != 3 or not all(parts):
        return False
    head = parts[0]
    try:
        raw = base64.urlsafe_b64decode(head + "=" * (-len(head) % 4))
        header = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001 - any decode failure means "not a JWT"
        return False
    return isinstance(header, dict) and "alg" in header


# --- detection -------------------------------------------------------------

# Provider-prefixed credentials only. A generic entropy heuristic would redact
# every commit hash and asset digest in the corpus; a known prefix does not.
_API_KEY_RE = re.compile(
    r"\b(?:"
    r"sk-[A-Za-z0-9_-]{16,}"                     # OpenAI-style
    r"|sk-ant-[A-Za-z0-9_-]{16,}"                # Anthropic
    r"|gh[pousr]_[A-Za-z0-9]{16,}"               # GitHub
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|AKIA[0-9A-Z]{16}"                         # AWS access key id
    r"|ASIA[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_-]{35}"                    # Google API key
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"             # Slack
    r"|glpat-[A-Za-z0-9_-]{16,}"                 # GitLab
    r"|npm_[A-Za-z0-9]{30,}"
    r"|dop_v1_[a-f0-9]{64}"                      # DigitalOcean
    r"|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"  # SendGrid
    r"|rk_live_[A-Za-z0-9]{16,}|sk_live_[A-Za-z0-9]{16,}|pk_live_[A-Za-z0-9]{16,}"
    r")\b"
)
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"
    r".*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
    re.DOTALL,
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}\b")
# IBANs appear either contiguous ("DE89370400440532013000") or grouped in fours
# ("GB82 WEST 1234 5698 7654 32"). A single permissive pattern over "separator
# then alphanumerics" happily swallows the next word of the sentence, so the
# candidate match is trimmed back to its longest validating prefix below.
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[A-Za-z0-9]{11,30}|(?:[ -][A-Za-z0-9]{2,4}){2,10})\b")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
_IPV6_RE = re.compile(
    r"(?<![:.\w])(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}"
    r"|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}"
    r"|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}"
    r")(?![:.\w])"
)
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
# Separators or a leading + are required, so bare digit runs (order numbers,
# prices, years) stay put.
_PHONE_RES = (
    re.compile(r"(?<![\w.])(?:\+?\d{1,3}[ .-])?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?![\w])"),
    re.compile(r"(?<![\w.])\+\d[\d .-]{6,}\d(?![\w])"),
)
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_BTC_RE = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62})\b")
# UK National Insurance number: two prefix letters, six digits, a suffix letter.
_NINO_RE = re.compile(r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b")
_DIGIT_RUN_RE = re.compile(r"\d(?:[ .-]?\d)*")


# Dotted-quad version strings are indistinguishable from IPv4 addresses in
# isolation, so use the one cue that is actually present: what precedes them.
_VERSION_CONTEXT_RE = re.compile(r"(?:\bv|\bversion\s+|\brelease\s+|\bbuild\s+)$", re.IGNORECASE)


def _regex_spans(text: str, regex: re.Pattern, entity: Entity,
                 validator=None) -> List[Span]:
    spans: List[Span] = []
    for match in regex.finditer(text):
        value = match.group(0)
        if validator is not None and not validator(value):
            continue
        if entity is Entity.IP_ADDRESS and _VERSION_CONTEXT_RE.search(text[:match.start()][-12:]):
            continue
        spans.append(Span(match.start(), match.end(), entity, value))
    return spans


def _iban_spans(text: str) -> List[Span]:
    """IBAN spans, trimming a greedy candidate back to its longest valid prefix.

    Regex alone cannot know where an IBAN ends: "GB82 WEST 1234 5698 7654 32
    please" is one uninterrupted run of separator-and-alphanumerics. The mod-97
    checksum does know, so let it decide — drop trailing groups until the number
    validates, and take the first prefix that does.
    """
    spans: List[Span] = []
    for match in _IBAN_RE.finditer(text):
        candidate = match.group(0)
        while len(candidate) >= 15:
            if iban_valid(candidate):
                spans.append(Span(match.start(), match.start() + len(candidate),
                                  Entity.IBAN, candidate))
                break
            cut = max(candidate.rfind(" "), candidate.rfind("-"))
            if cut <= 4:
                break
            candidate = candidate[:cut]
    return spans


def _digit_spans(text: str) -> List[Span]:
    """Card and SSN detection over digit runs, so every separator variant
    ("888-88-8888", "888 88 8888", "888888888") collapses to one rule."""
    spans: List[Span] = []
    for match in _DIGIT_RUN_RE.finditer(text):
        run = match.group(0)
        digits = "".join(ch for ch in run if ch.isdigit())
        offsets = [match.start() + i for i, ch in enumerate(run) if ch.isdigit()]
        if not offsets:
            continue
        start, end = offsets[0], offsets[-1] + 1
        value = text[start:end]
        if 13 <= len(digits) <= 19 and luhn_valid(digits):
            spans.append(Span(start, end, Entity.CREDIT_CARD, value))
        elif len(digits) == 9 and "." not in run and valid_ssn(digits):
            # Dots disqualify: "192.168.1.42" has nine digits and satisfies every
            # SSN structural rule, and SSN outranks IP_ADDRESS on overlap — so
            # without this an ordinary private IP is redacted as a social
            # security number. No one writes an SSN with dots.
            spans.append(Span(start, end, Entity.SSN, value))
    return spans


def detect(text: str) -> List[Span]:
    """Every sensitive span in ``text``, before overlap resolution."""
    spans: List[Span] = []
    spans += _regex_spans(text, _PRIVATE_KEY_RE, Entity.PRIVATE_KEY)
    spans += _regex_spans(text, _JWT_RE, Entity.JWT, jwt_valid)
    spans += _regex_spans(text, _API_KEY_RE, Entity.API_KEY)
    spans += _regex_spans(text, _EMAIL_RE, Entity.EMAIL)
    spans += _iban_spans(text)
    spans += _regex_spans(text, _IPV4_RE, Entity.IP_ADDRESS)
    spans += _regex_spans(text, _IPV6_RE, Entity.IP_ADDRESS)
    spans += _regex_spans(text, _MAC_RE, Entity.MAC_ADDRESS)
    spans += _regex_spans(text, _ETH_RE, Entity.CRYPTO_ADDRESS)
    spans += _regex_spans(text, _BTC_RE, Entity.CRYPTO_ADDRESS)
    spans += _regex_spans(text, _NINO_RE, Entity.NATIONAL_ID)
    for regex in _PHONE_RES:
        spans += _regex_spans(text, regex, Entity.PHONE)
    spans += _digit_spans(text)
    return spans


def _merge(spans: Sequence[Span]) -> List[Span]:
    """Reduce overlapping spans to a disjoint set. Higher priority wins; ties go
    to the longer span. Biased toward keeping a redaction: on any overlap the
    survivor covers both byte ranges, so nothing sensitive is left exposed by a
    partial match."""
    if len(spans) < 2:
        return list(spans)
    ordered = sorted(spans, key=lambda s: (s.start, -s.end))
    out: List[Span] = []
    for span in ordered:
        if not out or span.start >= out[-1].end:
            out.append(span)
            continue
        prev = out[-1]
        if prev.priority != span.priority:
            winner = prev if prev.priority > span.priority else span
        else:
            winner = prev if (prev.end - prev.start) >= (span.end - span.start) else span
        out[-1] = Span(min(prev.start, span.start), max(prev.end, span.end),
                       winner.entity, winner.value)
    return out


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().lower()


# --- public API ------------------------------------------------------------

def redact(
    text: str,
    keep: Iterable[Entity] = (),
    *,
    nonce: Optional[str] = None,
) -> Redaction:
    """Replace sensitive values with typed placeholders.

    Entities in ``keep`` are detected but left in place — useful when downstream
    logic genuinely needs the real value (keeping ``IP_ADDRESS`` in a log
    triage flow, say). The same value always maps to the same placeholder within
    one call, so a document mentioning an address twice still reads coherently.
    """
    keep_set = set(keep)
    if not text:
        return Redaction(text=text, count=0, summary="", nonce="")

    spans = [s for s in _merge(detect(text)) if s.entity not in keep_set]
    if not spans:
        return Redaction(text=text, count=0, summary="", nonce="")

    nonce = nonce or secrets.token_hex(2)
    forward: Dict[str, str] = {}
    reverse: Dict[str, str] = {}
    counters: Dict[str, int] = {}
    label_counts: Dict[str, int] = {}
    label_order: List[str] = []

    pieces: List[str] = []
    cursor = 0
    for span in spans:                      # _merge returns them in order
        label = span.entity.value
        key = f"{label}:{_normalize(span.value)}"
        token = forward.get(key)
        if token is None:
            counters[label] = counters.get(label, 0) + 1
            token = f"[{label}_{counters[label]}_{nonce}]"
            forward[key] = token
            reverse[token] = span.value
        pieces.append(text[cursor:span.start])
        pieces.append(token)
        cursor = span.end
        if label not in label_counts:
            label_order.append(label)
        label_counts[label] = label_counts.get(label, 0) + 1
    pieces.append(text[cursor:])

    return Redaction(
        text="".join(pieces),
        count=len(spans),
        summary=", ".join(f"{label}×{label_counts[label]}" for label in label_order),
        map=reverse,
        nonce=nonce,
        entities={s.entity for s in spans},
    )


def rehydrate(text: str, mapping: Dict[str, str]) -> str:
    """Restore original values from a :func:`redact` map.

    Only tokens present in ``mapping`` are replaced, and because every token
    carries that redaction's random nonce, a placeholder an attacker planted in
    the source can never be rehydrated into a real value. Unknown placeholders
    are left exactly as they are.
    """
    if not text or not mapping:
        return text
    # Longest first so [EMAIL_10_ab12] is not shadowed by [EMAIL_1_ab12].
    pattern = re.compile("|".join(re.escape(t) for t in sorted(mapping, key=len, reverse=True)))
    return pattern.sub(lambda m: mapping[m.group(0)], text)
