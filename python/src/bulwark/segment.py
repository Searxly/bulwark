"""Locate an injection inside a document instead of judging the whole thing.

A page-level verdict forces a bad choice. "This 4,000-word article contains an
injection" leaves you blocking the article — and the attacker, who only had to
add one poisoned sentence to a page you wanted, has denied you the content. Do
that a few times and the operator turns the guard off, which is the attack
working perfectly.

Segment analysis scores each passage on its own, so the answer becomes "the
injection is in paragraph 7, and paragraphs 1-6 and 8-40 are clean". From there
:func:`neutralize` excises just the poisoned passages and hands the model a
document that is still worth summarizing. The attacker loses their payload and
keeps none of their leverage.

The report also yields a **contamination ratio** — how much of the document is
hostile. A page that is 2% injection is a normal page someone poisoned; a page
that is 80% injection is an attack wearing a page as a costume, and callers may
reasonably treat the two differently.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from . import detect as _detect
from .types import Finding, Severity

# Segmentation budget. Detection is ~70 regexes per segment, so an unbounded
# split over a large document multiplies the scan cost by the segment count.
MAX_SEGMENTS = 250
MIN_SEGMENT_CHARS = 40          # shorter runs merge into their neighbour
LONG_SEGMENT_CHARS = 1_200      # paragraphs above this are split into sentences

DEFAULT_PLACEHOLDER = "[removed: passage containing instructions addressed to the assistant]"

_PARAGRAPH_SPLIT_RE = re.compile(r"\n[ \t]*\n")
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?。！？])[ \t]+(?=[^\s])|\n")


@dataclass
class Segment:
    """One passage of the document, scored on its own."""

    text: str
    start: int
    end: int
    score: float
    risk: Severity
    injected: bool
    findings: List[Finding] = field(default_factory=list)

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass
class SegmentReport:
    """Where the injection is, and how much of the document it occupies."""

    segments: List[Segment]
    contamination: float          # share of characters inside injected segments
    injected_count: int
    worst: Optional[Segment] = None

    @property
    def clean(self) -> bool:
        return self.injected_count == 0

    def injected_segments(self) -> List[Segment]:
        return [s for s in self.segments if s.injected]

    def summary(self) -> str:
        if self.clean:
            return f"{len(self.segments)} segment(s), none flagged"
        return (
            f"{self.injected_count}/{len(self.segments)} segment(s) flagged, "
            f"{self.contamination:.0%} of the text by length"
        )


def _spans(text: str) -> List[Tuple[int, int]]:
    """Split into paragraph spans, breaking overlong paragraphs into sentences
    and merging runts, keeping every offset exact against the original text."""
    if not text:
        return []

    raw: List[Tuple[int, int]] = []
    cursor = 0
    for match in _PARAGRAPH_SPLIT_RE.finditer(text):
        if match.start() > cursor:
            raw.append((cursor, match.start()))
        cursor = match.end()
    if cursor < len(text):
        raw.append((cursor, len(text)))
    if not raw:
        raw = [(0, len(text))]

    # Break paragraphs that are long enough to hide a payload in a corner.
    split: List[Tuple[int, int]] = []
    for start, end in raw:
        if end - start <= LONG_SEGMENT_CHARS:
            split.append((start, end))
            continue
        piece_start = start
        for match in _SENTENCE_SPLIT_RE.finditer(text, start, end):
            if match.end() > piece_start:
                split.append((piece_start, match.start()))
                piece_start = match.end()
        if piece_start < end:
            split.append((piece_start, end))

    # Merge runts forward so a one-word line doesn't become its own segment.
    merged: List[Tuple[int, int]] = []
    for start, end in split:
        if merged and (end - start) < MIN_SEGMENT_CHARS:
            merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))

    # Enforce the budget by fusing neighbours evenly rather than dropping tail
    # segments — losing the end of a document is exactly where a payload hides.
    while len(merged) > MAX_SEGMENTS:
        fused: List[Tuple[int, int]] = []
        for i in range(0, len(merged), 2):
            pair = merged[i:i + 2]
            fused.append((pair[0][0], pair[-1][1]))
        merged = fused

    return [(s, e) for s, e in merged if text[s:e].strip()]


def analyze_segments(
    text: str,
    *,
    threshold: float = 0.5,
    use_heuristics: bool = False,
    fold: bool = True,
) -> SegmentReport:
    """Score every passage of ``text`` independently.

    ``use_heuristics`` defaults to False here on purpose: the density
    heuristics measure a property of a whole document (what fraction of its
    lines are imperative), and applying them to a three-line segment turns any
    short instruction list into a hit.
    """
    from .sanitize import fold_detection

    spans = _spans(text)
    segments: List[Segment] = []
    contaminated_chars = 0

    for start, end in spans:
        piece = text[start:end]
        result = _detect.scan(
            piece,
            threshold=threshold,
            use_heuristics=use_heuristics,
            also_scan=fold_detection(piece) if fold else None,
        )
        segment = Segment(
            text=piece,
            start=start,
            end=end,
            score=result.score,
            risk=result.risk,
            injected=result.injected,
            findings=result.findings,
        )
        segments.append(segment)
        if segment.injected:
            contaminated_chars += segment.length

    total = sum(s.length for s in segments) or 1
    injected = [s for s in segments if s.injected]
    return SegmentReport(
        segments=segments,
        contamination=round(contaminated_chars / total, 4),
        injected_count=len(injected),
        worst=max(segments, key=lambda s: s.score) if segments else None,
    )


def neutralize(
    text: str,
    report: Optional[SegmentReport] = None,
    *,
    threshold: float = 0.5,
    placeholder: str = DEFAULT_PLACEHOLDER,
    max_contamination: float = 0.75,
) -> Tuple[str, int]:
    """Excise the flagged passages, keeping the rest of the document intact.

    Returns ``(neutralized_text, passages_removed)``.

    When contamination exceeds ``max_contamination`` nothing is excised and the
    text is returned unchanged: at that point the document *is* the attack, and
    quietly handing back the 20% remainder would misrepresent it as a cleaned
    version of something real. Callers should block instead — which they can
    see from the report.
    """
    if report is None:
        report = analyze_segments(text, threshold=threshold)
    if report.clean or report.contamination > max_contamination:
        return text, 0

    out: List[str] = []
    cursor = 0
    removed = 0
    for segment in report.segments:
        if not segment.injected:
            continue
        out.append(text[cursor:segment.start])
        out.append(placeholder)
        cursor = segment.end
        removed += 1
    out.append(text[cursor:])

    # Collapse the blank space left behind by an excised paragraph.
    joined = re.sub(r"\n{3,}", "\n\n", "".join(out))
    return joined.strip(), removed


# Short alias for use inside a pipeline that has already imported the module.
analyze = analyze_segments
