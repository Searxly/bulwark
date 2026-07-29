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
_ZERO_WIDTH = {
    0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x180E, 0x00AD,
    # Hangul fillers: render as nothing in every browser, and split a trigger
    # word as effectively as a zero-width space.
    0x115F, 0x1160, 0x3164, 0xFFA0,
    # Interlinear annotation controls and the combining grapheme joiner.
    0xFFF9, 0xFFFA, 0xFFFB, 0x034F,
    # Line/paragraph separators — invisible line breaks.
    0x2028, 0x2029,
    # Mongolian vowel separator and Khmer invisible spacers.
    0x17B4, 0x17B5,
}

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
    r"display\s*:\s*none"
    r"|visibility\s*:\s*hidden"
    # Zero only. `opacity:0` hides text; `opacity:0.95` does not, and the
    # previous pattern matched both — silently deleting visible content.
    r"|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$|!)"
    r"|font-size\s*:\s*0(?:\.0+)?(?:px|em|rem|pt|%)?\s*(?:;|$|!)"
    r"|(?:width|height)\s*:\s*0(?:\.0+)?(?:px|em|rem|%)?\s*(?:;|$|!)"
    r"|text-indent\s*:\s*-\d{4,}"
    r"|clip-path\s*:\s*inset\(\s*(?:100%|50%\s+50%)"
    r"|position\s*:\s*absolute[^;]*;\s*(?:left|top)\s*:\s*-\d{4,}",
    re.IGNORECASE
)
_SKIP_TAGS = {
    "script", "style", "noscript", "template", "svg", "math", "head",
    # Fallback content that only renders when the feature is unavailable —
    # in a scraped page it is text the reader never saw.
    "noembed", "noframes", "iframe", "object", "applet", "canvas", "audio", "video",
}
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


def strip_marks(text: str) -> str:
    """Drop combining marks so stacked diacritics can't hide a trigger word.

    ``i̇̈g̈n̈ör̈ë`` reads as "ignore" to a model and to a human squinting at it, but
    every ASCII signature misses it. Decomposing and dropping category-Mn
    characters folds it back. Not 1:1 — the result is shorter — so this belongs
    to the flattened view, which carries its own offset map.
    """
    decomposed = unicodedata.normalize("NFD", text)
    stripped = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return unicodedata.normalize("NFC", stripped)


def fold_detection(text: str) -> str:
    """Build the detector's second-pass copy: fold leetspeak, then cross-script
    homoglyphs. Both are 1:1 so detection offsets stay aligned. Detection-only."""
    return fold_confusables(fold_leet(text))


_SOFT_HYPHENS = "-­‐‑"


def flatten_for_detection(text: str) -> "Tuple[str, List[int]]":
    """Collapse whitespace and rejoin hyphenated line breaks, keeping an offset map.

    Signatures join their trigger words with bounded spans like ``.{0,40}?``, and
    in Python, JavaScript and ICU alike ``.`` does not cross a newline. So the
    canonical payload — *ignore all previous instructions* — stops matching the
    moment it is hard-wrapped, which ordinary 72-column text does by accident and
    an attacker does on purpose. PDF and typeset sources add the second half of
    the problem: ``dis-\\nregard`` splits the word itself.

    Turning on DOTALL would be the wrong fix. It would let a bounded span reach
    across paragraph boundaries and pair up words that merely happen to sit near
    each other, trading a false negative for a false positive.

    Instead this builds a flattened *view*: every whitespace run becomes one
    space and every hyphen-at-a-line-break is closed up, so proximity limits
    still mean what they say — they just stop counting line breaks as content.
    The returned list maps each character of the view back to its offset in the
    original, so a match found here still reports a span the caller can use.
    """
    out: List[str] = []
    index: List[int] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in _SOFT_HYPHENS and out and out[-1].isalnum():
            j = i + 1
            while j < n and text[j] in " \t":
                j += 1
            if j < n and text[j] in "\r\n":
                while j < n and text[j] in "\r\n \t":
                    j += 1
                if j < n and text[j].isalnum():
                    i = j        # drop the hyphen and the break; the word closes up
                    continue
        if ch.isspace():
            if out and out[-1] != " ":
                out.append(" ")
                index.append(i)
            i += 1
            continue
        out.append(ch)
        index.append(i)
        i += 1
    return "".join(out), index


def map_span(span: "Tuple[int, int]", index: "List[int]", original_length: int) -> "Tuple[int, int]":
    """Translate a span found in a flattened view back to the original text."""
    start, end = span
    if not index:
        return span
    start = index[start] if 0 <= start < len(index) else original_length
    last = min(max(end - 1, 0), len(index) - 1)
    return start, min(index[last] + 1, original_length)


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

    def handle_startendtag(self, tag, attrs):  # type: ignore[override]
        # XHTML self-closing form: `<div style="display:none"/>`. The stdlib
        # parser routes these here rather than through start+end, and without
        # this the skip depth went out of balance and hidden subtrees leaked.
        if tag in _SKIP_TAGS:
            self.skipped_blocks += 1
        elif _is_hidden(attrs):
            self.hidden_elements += 1
        if tag in _BLOCK_TAGS:
            self.parts.append("\n")

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
            key = "variation_selectors" if 0xFE00 <= cp <= 0xFE0F else "variation_selectors_supplementary"
            counts[key] = counts.get(key, 0) + 1
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
    # Only the supplementary selectors (U+E0100-E01EF) are a smuggling channel.
    # U+FE00-FE0F are ordinary emoji presentation selectors: one of those in a
    # page is not evidence of anything, and reporting it at HIGH severity made
    # any document containing an emoji score as an attack.
    if counts.get("variation_selectors_supplementary"):
        findings.append(Finding(
            Stage.SANITIZE, "variation_smuggling", Severity.HIGH,
            f"Removed {counts['variation_selectors_supplementary']} supplementary variation "
            f"selector(s) (a data-smuggling channel)",
            weight=0.66,
        ))
    if counts.get("variation_selectors"):
        findings.append(Finding(
            Stage.SANITIZE, "variation_selector", Severity.INFO,
            f"Removed {counts['variation_selectors']} emoji variation selector(s)",
            weight=0.0,
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
