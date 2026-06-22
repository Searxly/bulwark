"""Strip invisible and structural injection vectors from untrusted text.

Removes ASCII smuggling (Unicode tag chars), bidi controls, zero-width and
control characters, and CSS-hidden HTML, then NFKC-normalizes. Cross-script
homoglyph folding (``fold_confusables``) runs on the detection copy only, never
on text shown to the model.
"""

from __future__ import annotations

import html
import re
import unicodedata
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple

from .types import Finding, SanitizeResult, Severity, Stage

# Codepoints that are invisible and have no place in plain summarizable text.
_BIDI_CONTROLS = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}
_TAG_CHARS = set(range(0xE0000, 0xE0080))
_VARIATION_SELECTORS = set(range(0xFE00, 0xFE10)) | set(range(0xE0100, 0xE01F0))
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x180E, 0x00AD}

# Cross-script homoglyphs → ASCII (1:1 so detection offsets stay aligned).
# Covers the Cyrillic/Greek look-alikes used to disguise trigger words such as
# "ѕуѕtем", "іgnоrе", "рrоmрt". NFKC does NOT fold these, so we do it ourselves.
_CONFUSABLES: Dict[str, str] = {
    # Cyrillic lowercase
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ӏ": "l", "ԁ": "d", "к": "k",
    # Cyrillic uppercase
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "У": "Y", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    # Greek lowercase
    "ο": "o", "α": "a", "ρ": "p", "ν": "v", "ι": "i",
    "κ": "k", "ς": "c",
    # Greek uppercase
    "Ο": "O", "Α": "A", "Β": "B", "Ε": "E", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ρ": "P",
    "Τ": "T", "Υ": "Y", "Χ": "X", "Ζ": "Z",
    # Misc
    "ı": "i", "․": ".",
}
_CONFUSABLE_TABLE = {ord(k): v for k, v in _CONFUSABLES.items()}

# Leetspeak / digit-substitution map → ASCII letters (1:1, offsets stay aligned).
# Attackers swap letters for look-alike digits/symbols ("1gn0r3 pr3v10us") to slip
# past keyword filters while the model still reads the word. Like fold_confusables,
# this runs on the *detection* copy only — never on text shown to the model.
_LEET: Dict[str, str] = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
}
_LEET_TABLE = {ord(k): v for k, v in _LEET.items()}

_WS_RE = re.compile(r"[^\S\n]+")  # runs of horizontal whitespace (incl. Unicode spaces), keep newlines
_BLANKLINES_RE = re.compile(r"\n{3,}")
_HTMLISH_RE = re.compile(r"<(?:/?[a-zA-Z][\w:-]*\b|!--)")
_TAG_RE = re.compile(r"<[^>]+>")

_HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0(?:px|em|rem|%)?\b", re.IGNORECASE
)
_SKIP_TAGS = {"script", "style", "noscript", "template", "svg", "math", "head"}
_BLOCK_TAGS = {
    "p", "div", "br", "li", "ul", "ol", "tr", "table", "section", "article",
    "header", "footer", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre", "hr",
}
_VOID_TAGS = {"br", "img", "hr", "input", "meta", "link", "source", "area", "base", "col", "embed", "wbr"}


def fold_confusables(text: str) -> str:
    """Map cross-script homoglyphs to ASCII. Use on the *detection* copy only —
    never on text shown to the model, to avoid corrupting legitimate non-Latin
    content."""
    return text.translate(_CONFUSABLE_TABLE)


def fold_leet(text: str) -> str:
    """Map common leetspeak digit/symbol substitutions to ASCII letters. Like
    :func:`fold_confusables`, this is for the *detection* copy only — it would
    corrupt legitimate text shown to the model."""
    return text.translate(_LEET_TABLE)


def fold_detection(text: str) -> str:
    """Build the detector's second-pass copy: fold leetspeak, then cross-script
    homoglyphs. Both are 1:1 so detection offsets stay aligned. Detection-only."""
    return fold_confusables(fold_leet(text))


def _is_hidden(attrs: List[Tuple[str, Optional[str]]]) -> bool:
    for name, value in attrs:
        lname = name.lower()
        if lname == "hidden":
            return True
        if lname == "aria-hidden" and (value or "").lower() == "true":
            return True
        if lname == "style" and value and _HIDDEN_STYLE_RE.search(value):
            return True
    return False


class _HTMLTextExtractor(HTMLParser):
    """Walk HTML, emitting only the text a human would actually see."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self._skip_depth = 0           # inside <script>/<style>/hidden subtree
        self._stack: List[Tuple[str, bool]] = []
        self.comments = 0
        self.skipped_blocks = 0
        self.hidden_elements = 0

    def handle_starttag(self, tag, attrs):  # type: ignore[override]
        hidden = tag in _SKIP_TAGS or _is_hidden(attrs)
        if hidden:
            if tag in _SKIP_TAGS:
                self.skipped_blocks += 1
            else:
                self.hidden_elements += 1
            self._skip_depth += 1
        if tag not in _VOID_TAGS:
            self._stack.append((tag, hidden))
        elif hidden:
            # A void element can't enclose anything; undo the skip increment.
            self._skip_depth -= 1
        if tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):  # type: ignore[override]
        for i in range(len(self._stack) - 1, -1, -1):
            t, hidden = self._stack[i]
            if t == tag:
                if hidden and self._skip_depth > 0:
                    self._skip_depth -= 1
                del self._stack[i:]
                break
        if tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data):  # type: ignore[override]
        if self._skip_depth == 0:
            self.parts.append(data)

    def handle_comment(self, data):  # type: ignore[override]
        self.comments += 1

    def text(self) -> str:
        return "".join(self.parts)


def _excerpt(text: str, limit: int = 80) -> str:
    s = text.strip().replace("\n", " ")
    return s if len(s) <= limit else s[: limit - 1] + "…"


def strip_invisible(text: str, *, keep_emoji_variation: bool = False) -> "Tuple[str, Dict[str, int], List[Finding]]":
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


def strip_html(text: str) -> "Tuple[str, Dict[str, int], List[Finding]]":
    """Extract visible text from HTML, dropping scripts/styles/comments/hidden
    elements. Uses the stdlib HTML parser (handles nesting); falls back to a
    regex tag-strip if parsing fails."""
    counts: Dict[str, int] = {}
    findings: List[Finding] = []
    try:
        parser = _HTMLTextExtractor()
        parser.feed(text)
        parser.close()
        cleaned = parser.text()
        if parser.comments:
            counts["html_comments"] = parser.comments
        if parser.skipped_blocks:
            counts["script_style"] = parser.skipped_blocks
        if parser.hidden_elements:
            counts["hidden_elements"] = parser.hidden_elements
            findings.append(Finding(
                Stage.SANITIZE, "hidden_html", Severity.MEDIUM,
                f"Removed {parser.hidden_elements} visually hidden HTML element(s) (text invisible to humans)",
                weight=0.55,
            ))
    except Exception:  # pragma: no cover - parser is very lenient
        cleaned = _TAG_RE.sub(" ", re.sub(r"<!--.*?-->", " ", text, flags=re.DOTALL))
        cleaned = html.unescape(cleaned)
    return cleaned, counts, findings


def normalize(text: str) -> str:
    """NFKC-normalize (folds full-width/ligature tricks) and tidy whitespace."""
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
    """Run the full sanitization stage and return a :class:`SanitizeResult`.

    Note: the returned ``text`` is content-preserving (safe to summarize). Use
    :func:`fold_confusables` on it to build the copy passed to the detector.
    """
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
