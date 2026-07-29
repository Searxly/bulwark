"""Tell a document that *performs* an attack from one that *discusses* one.

The most common false positive in prompt-injection detection is a security
article. A page explaining how injection works quotes real payloads; an API
reference documenting chat templates prints real role tokens; a changelog says
"this release overrides the previous configuration". These are the exact
documents a security-conscious user is most likely to feed to a summarizer, and
flagging them is how a guard earns a reputation for crying wolf and gets
switched off.

The difference between quoting an instruction and issuing one is *context*:

* the payload sits in a code fence, a blockquote, or quotation marks; and
* the surrounding prose is talking *about* attacks — "an attacker embeds…",
  "for example…", "this payload demonstrates…"; and
* the document as a whole reads like security writing.

Any one of those alone is weak evidence, and — critically — cheap for an
attacker to fake. Wrapping a payload in a code fence costs nothing. So a single
signal earns only a small discount, and the discount deepens only as
*independent* signals stack up. To reach the largest discount an attacker must
fence their payload, quote it, surround it with "this is a malicious example"
framing, and make the whole page read as a security write-up — at which point
they have spent the attack's own persuasive power telling the model that the
text is a quoted specimen. **The evasion weakens the payload.** That property is
the reason this is safe to do at all.

The discount is also floored well above zero. Context can make a finding quieter;
it can never silence one, so this can never become a reliable bypass. Everything
downstream — spotlighting, the hardened prompt, output validation — is unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple

from .types import Finding

# Discount by number of independent context signals. Never reaches zero: a
# discounted finding still contributes to the score and still appears in the
# report, so a "quoted" payload can never be silently dropped.
_DISCOUNT_BY_SIGNALS = (1.00, 0.78, 0.50, 0.34, 0.30)
MIN_DISCOUNT = 0.30

# Phrases that mark prose as *about* attacks rather than *being* one. Chosen to
# be the vocabulary of analysis, not of instruction.
_META_MARKERS = (
    "for example", "for instance", "e.g.", "such as", "consider the following",
    "the following text", "sample payload", "example payload", "attack string",
    "proof of concept", "demonstrat", "illustrat", "example of",
    "attacker", "adversar", "malicious", "payload", "exploit", "vulnerab",
    "prompt injection", "prompt-injection", "jailbreak", "injected", "injection",
    "red team", "red-team", "threat model", "mitigat", "guardrail", "sanitiz",
    "security research", "advisory", "cve-", "owasp", "write-up", "writeup",
    "in this lesson", "in this article", "this post", "we tested", "we found",
    "reported by", "disclosure", "verbatim", "quoted above", "quoted below",
    "would look like", "looks like this", "test case", "regression test",
    "do not run this", "harmless example", "defanged",
)
# Reaching this many *distinct* markers makes the whole document read as
# analysis. Set high enough that one passing mention of "attacker" is not enough.
_DOC_META_THRESHOLD = 4

_FENCE_RE = re.compile(r"(?:^|\n)(```|~~~)[^\n]*\n.*?(?:\n\1|\Z)", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`[^`\n]{1,400}`")
_HTML_CODE_RE = re.compile(r"<(pre|code|samp|kbd)\b[^>]*>.*?</\1\s*>", re.DOTALL | re.IGNORECASE)
_INDENTED_BLOCK_RE = re.compile(r"(?:^|\n)(?:(?:[ ]{4}|\t)[^\n]*\n){2,}")
_BLOCKQUOTE_RE = re.compile(r"(?:^|\n)(?:[ \t]*>[^\n]*\n?){1,}")
# Paired quotation marks. Straight single quotes are excluded: apostrophes make
# them unpairable in ordinary English and the resulting spans are nonsense.
_QUOTE_RES = (
    re.compile(r'"[^"\n]{8,600}"'),
    re.compile(r"“[^”\n]{8,600}”"),
    re.compile(r"‘[^’\n]{8,600}’"),
    re.compile(r"«[^»\n]{8,600}»"),
    re.compile(r"「[^」\n]{8,600}」"),
)

# How far back to look for framing prose around a match.
_LOOKBEHIND_CHARS = 200
_LOOKAHEAD_CHARS = 90


@dataclass
class ContextProfile:
    """Where the quoting constructs are, and how meta the document reads."""

    code_spans: List[Tuple[int, int]] = field(default_factory=list)
    quote_spans: List[Tuple[int, int]] = field(default_factory=list)
    meta_markers: List[str] = field(default_factory=list)
    text_length: int = 0

    @property
    def document_is_meta(self) -> bool:
        return len(self.meta_markers) >= _DOC_META_THRESHOLD

    @property
    def quoted_fraction(self) -> float:
        """Share of the document inside code or quotes. A page that is mostly
        quoted material is a specimen collection, not a message."""
        if not self.text_length:
            return 0.0
        covered = _merge_spans(self.code_spans + self.quote_spans)
        return min(1.0, sum(e - s for s, e in covered) / self.text_length)


def _merge_spans(spans: Sequence[Tuple[int, int]]) -> List[Tuple[int, int]]:
    if not spans:
        return []
    ordered = sorted(spans)
    out = [list(ordered[0])]
    for start, end in ordered[1:]:
        if start <= out[-1][1]:
            out[-1][1] = max(out[-1][1], end)
        else:
            out.append([start, end])
    return [(s, e) for s, e in out]


def _spans_of(regexes: Iterable[re.Pattern], text: str, limit: int = 400) -> List[Tuple[int, int]]:
    spans: List[Tuple[int, int]] = []
    for regex in regexes:
        for match in regex.finditer(text):
            spans.append((match.start(), match.end()))
            if len(spans) >= limit:
                return _merge_spans(spans)
    return _merge_spans(spans)


def profile(text: str) -> ContextProfile:
    """Map the quoting constructs and meta-discourse in ``text``."""
    if not text:
        return ContextProfile()

    code = _spans_of((_FENCE_RE, _HTML_CODE_RE, _INLINE_CODE_RE, _INDENTED_BLOCK_RE), text)
    quotes = _spans_of((_BLOCKQUOTE_RE,) + _QUOTE_RES, text)

    lowered = text.lower()
    markers = [m for m in _META_MARKERS if m in lowered]

    return ContextProfile(
        code_spans=code,
        quote_spans=quotes,
        meta_markers=markers,
        text_length=len(text),
    )


def _inside(span: Tuple[int, int], spans: Sequence[Tuple[int, int]]) -> bool:
    start, end = span
    midpoint = (start + end) // 2
    for s, e in spans:
        if s <= midpoint < e:
            return True
    return False


def signals_for(text: str, span: Tuple[int, int], prof: ContextProfile) -> List[str]:
    """Which independent context signals apply to a match at ``span``."""
    signals: List[str] = []
    if _inside(span, prof.code_spans):
        signals.append("in_code")
    if _inside(span, prof.quote_spans):
        signals.append("quoted")

    start, end = span
    window = text[max(0, start - _LOOKBEHIND_CHARS):min(len(text), end + _LOOKAHEAD_CHARS)].lower()
    if any(marker in window for marker in _META_MARKERS):
        signals.append("meta_nearby")

    if prof.document_is_meta:
        signals.append("document_is_meta")
    return signals


def discount_for(text: str, span: Optional[Tuple[int, int]], prof: ContextProfile) -> Tuple[float, List[str]]:
    """Weight multiplier for a finding at ``span``, plus the signals behind it."""
    if span is None:
        return 1.0, []
    signals = signals_for(text, span, prof)
    factor = _DISCOUNT_BY_SIGNALS[min(len(signals), len(_DISCOUNT_BY_SIGNALS) - 1)]
    return max(MIN_DISCOUNT, factor), signals


def apply(text: str, findings: Sequence[Finding], prof: Optional[ContextProfile] = None) -> List[Finding]:
    """Return ``findings`` re-weighted for quoting context.

    Findings without a span (sanitization results, density heuristics) are
    returned untouched: they describe the document as a whole, and "the document
    as a whole" has no enclosing quotation to sit inside.
    """
    if not findings:
        return list(findings)
    prof = prof if prof is not None else profile(text)
    if not prof.code_spans and not prof.quote_spans and not prof.document_is_meta:
        return list(findings)

    out: List[Finding] = []
    for finding in findings:
        factor, signals = discount_for(text, finding.span, prof)
        if factor >= 1.0 or finding.weight <= 0:
            out.append(finding)
            continue
        out.append(Finding(
            stage=finding.stage,
            category=finding.category,
            severity=finding.severity,
            message=f"{finding.message} (discounted ×{factor:.2f}: {', '.join(signals)})",
            weight=round(finding.weight * factor, 4),
            excerpt=finding.excerpt,
            span=finding.span,
            pattern_id=finding.pattern_id,
        ))
    return out
