"""Stage 1 — sanitization.

Removes the invisible and structural tricks attackers use to smuggle
instructions past both humans and naive pattern matchers:

* Unicode *Tag* characters (U+E0000–U+E007F) — "ASCII smuggling": a full
  hidden instruction can be encoded in characters that render as nothing.
* Bidirectional controls (U+202A–U+202E, U+2066–U+2069, …) — "Trojan Source":
  text that reads one way but is ordered another.
* Zero-width and other invisible separators used to break up trigger words
  (``i<ZWSP>gnore``) so they dodge keyword filters.
* Variation-selector smuggling (U+FE00–U+FE0F, U+E0100–U+E01EF).
* C0/C1 control characters.
* HTML comments, ``<script>``/``<style>`` blocks and CSS-hidden elements
  (``display:none``, ``visibility:hidden``, ``opacity:0``, ``aria-hidden``)
  whose only purpose on a page is to feed a model text a human never sees.

Confusable evasion (full-width ``ｉｇｎｏｒｅ``, etc.) is folded away with NFKC
normalization so the detector downstream sees canonical ASCII.
"""

from __future__ import annotations

import html
import re
import unicodedata
from typing import Dict, List, Optional

from .types import Finding, SanitizeResult, Severity, Stage

# Codepoints that are invisible and have no place in plain summarizable text.
_BIDI_CONTROLS = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}
_TAG_CHARS = set(range(0xE0000, 0xE0080))
_VARIATION_SELECTORS = set(range(0xFE00, 0xFE10)) | set(range(0xE0100, 0xE01F0))
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x180E, 0x00AD}

_SCRIPT_STYLE_RE = re.compile(r"<(script|style|template|noscript)\b[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_HIDDEN_STYLE_RE = re.compile(
    r"<(?P<tag>[a-zA-Z][\w:-]*)\b[^>]*?(?:"
    r"style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0)"
    r"|aria-hidden\s*=\s*[\"']true[\"']|hidden(?=[\s>]))"
    r"[^>]*>.*?</(?P=tag)\s*>",
    re.IGNORECASE | re.DOTALL,
)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"[^\S\n]+")  # runs of horizontal whitespace (incl. Unicode spaces), keep newlines
_BLANKLINES_RE = re.compile(r"\n{3,}")
_HTMLISH_RE = re.compile(r"<(?:/?[a-zA-Z][\w:-]*\b|!--)")


def _excerpt(text: str, limit: int = 80) -> str:
    s = text.strip().replace("\n", " ")
    return s if len(s) <= limit else s[: limit - 1] + "…"


def strip_invisible(text: str, *, keep_emoji_variation: bool = False) -> "tuple[str, Dict[str, int], List[Finding]]":
    """Drop invisible/control characters. Returns (clean, counts, findings)."""
    counts: Dict[str, int] = {}
    out: List[str] = []
    for ch in text:
        cp = ord(ch)
        if cp in _TAG_CHARS:
            counts["tag_chars"] = counts.get("tag_chars", 0) + 1
            continue
        if cp in _BIDI_CONTROLS:
            counts["bidi_controls"] = counts.get("bidi_controls", 0) + 1
            continue
        if cp in _VARIATION_SELECTORS:
            if keep_emoji_variation and 0xFE00 <= cp <= 0xFE0F:
                out.append(ch)
                continue
            counts["variation_selectors"] = counts.get("variation_selectors", 0) + 1
            continue
        if cp in _ZERO_WIDTH:
            counts["zero_width"] = counts.get("zero_width", 0) + 1
            continue
        if ch in ("\t", "\n", "\r"):
            out.append(ch)
            continue
        # C0 (excluding tab/newline/cr above) and C1 control ranges + DEL.
        if cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
            counts["control_chars"] = counts.get("control_chars", 0) + 1
            continue
        out.append(ch)

    findings: List[Finding] = []
    if counts.get("tag_chars"):
        findings.append(Finding(
            Stage.SANITIZE, "ascii_smuggling", Severity.CRITICAL,
            f"Removed {counts['tag_chars']} Unicode Tag character(s) used to smuggle hidden text",
            weight=0.90,
        ))
    if counts.get("bidi_controls"):
        findings.append(Finding(
            Stage.SANITIZE, "bidi_control", Severity.HIGH,
            f"Removed {counts['bidi_controls']} bidirectional control character(s) (Trojan Source)",
            weight=0.62,
        ))
    if counts.get("variation_selectors"):
        findings.append(Finding(
            Stage.SANITIZE, "variation_smuggling", Severity.HIGH,
            f"Removed {counts['variation_selectors']} variation selector(s) (possible data smuggling)",
            weight=0.66,
        ))
    if counts.get("zero_width"):
        findings.append(Finding(
            Stage.SANITIZE, "zero_width", Severity.LOW,
            f"Removed {counts['zero_width']} zero-width character(s) (often used to split trigger words)",
            weight=0.24,
        ))
    if counts.get("control_chars"):
        findings.append(Finding(
            Stage.SANITIZE, "control_chars", Severity.LOW,
            f"Removed {counts['control_chars']} control character(s)",
            weight=0.15,
        ))
    return "".join(out), counts, findings


def strip_html(text: str) -> "tuple[str, Dict[str, int], List[Finding]]":
    """Remove scripts/styles/comments/hidden elements and extract visible text.

    Regex-based and dependency-free. For complex real-world HTML, install the
    ``html`` extra (BeautifulSoup) and pass already-extracted text; this stays
    as a robust last line of defence either way.
    """
    counts: Dict[str, int] = {}
    findings: List[Finding] = []

    def _count(pattern: re.Pattern, s: str, key: str) -> str:
        n = len(pattern.findall(s))
        if n:
            counts[key] = counts.get(key, 0) + n
        return pattern.sub(" ", s)

    cleaned = _count(_COMMENT_RE, text, "html_comments")
    cleaned = _count(_SCRIPT_STYLE_RE, cleaned, "script_style")
    hidden_matches = _HIDDEN_STYLE_RE.findall(cleaned)
    if hidden_matches:
        counts["hidden_elements"] = len(hidden_matches)
        findings.append(Finding(
            Stage.SANITIZE, "hidden_html", Severity.MEDIUM,
            f"Removed {len(hidden_matches)} visually hidden HTML element(s) (text invisible to humans)",
            weight=0.55,
        ))
    cleaned = _HIDDEN_STYLE_RE.sub(" ", cleaned)
    cleaned = _TAG_RE.sub(" ", cleaned)
    cleaned = html.unescape(cleaned)
    return cleaned, counts, findings


def normalize(text: str) -> str:
    """NFKC-normalize (folds full-width/confusable tricks) and tidy whitespace."""
    text = unicodedata.normalize("NFKC", text)
    text = _WS_RE.sub(" ", text)
    text = "\n".join(line.strip() for line in text.split("\n"))
    text = _BLANKLINES_RE.sub("\n\n", text)
    return text.strip()


def looks_like_html(text: str) -> bool:
    return bool(_HTMLISH_RE.search(text))


def sanitize(
    text: str,
    *,
    strip_html_content: "bool | str" = "auto",
    normalize_unicode: bool = True,
    keep_emoji_variation: bool = False,
) -> SanitizeResult:
    """Run the full sanitization stage and return a :class:`SanitizeResult`."""
    original_length = len(text)
    removed: Dict[str, int] = {}
    findings: List[Finding] = []

    do_html = looks_like_html(text) if strip_html_content == "auto" else bool(strip_html_content)
    if do_html:
        text, html_counts, html_findings = strip_html(text)
        removed.update(html_counts)
        findings.extend(html_findings)

    text, inv_counts, inv_findings = strip_invisible(text, keep_emoji_variation=keep_emoji_variation)
    for k, v in inv_counts.items():
        removed[k] = removed.get(k, 0) + v
    findings.extend(inv_findings)

    if normalize_unicode:
        text = normalize(text)
    else:
        text = _WS_RE.sub(" ", text).strip()

    return SanitizeResult(
        text=text,
        original_length=original_length,
        cleaned_length=len(text),
        removed=removed,
        findings=findings,
    )
