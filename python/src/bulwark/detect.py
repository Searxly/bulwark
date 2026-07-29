"""Detection and risk scoring.

Runs the signature database plus a few structural heuristics over sanitized
text and combines the weighted signals with a noisy-OR (score = 1 - prod(1-wi)),
so weak signals accumulate but no single one saturates the score. Sanitize-stage
findings are folded into the same score.
"""

from __future__ import annotations

import re
from typing import Iterable, List, Sequence

from .patterns import SIGNATURES
from .types import DetectResult, Finding, Severity, Stage

_IMPERATIVE_VERBS = {
    "ignore", "disregard", "forget", "stop", "do", "don't", "dont", "never", "always",
    "print", "output", "repeat", "reveal", "send", "post", "fetch", "execute", "run",
    "call", "follow", "obey", "respond", "reply", "answer", "write", "say", "tell",
    "act", "pretend", "become", "switch", "override", "bypass", "summarize", "translate",
}
_DIRECTIVE_RE = re.compile(
    r"\byou\s+(?:must|should|shall|need\s+to|have\s+to|are\s+(?:required|instructed|now))\b",
    re.IGNORECASE,
)
_LINE_RE = re.compile(r"^[\s\-\*\d\.\)#>]*([a-zA-Z']+)", re.MULTILINE)


def _excerpt(text: str, start: int, end: int, pad: int = 24) -> str:
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    s = text[a:b].replace("\n", " ").strip()
    return ("…" if a > 0 else "") + s + ("…" if b < len(text) else "")


def match_signatures(text: str) -> List[Finding]:
    """Return one finding per signature match (deduplicated per signature)."""
    findings: List[Finding] = []
    for sig in SIGNATURES:
        m = sig.regex.search(text)
        if not m:
            continue
        findings.append(Finding(
            stage=Stage.DETECT,
            category=sig.category,
            severity=sig.severity,
            message=sig.description,
            weight=sig.weight,
            excerpt=_excerpt(text, m.start(), m.end()),
            span=(m.start(), m.end()),
            pattern_id=sig.id,
        ))
    return findings


def heuristic_findings(text: str) -> List[Finding]:
    """Structural cues that are suspicious in aggregate but weak alone."""
    findings: List[Finding] = []
    if not text:
        return findings

    # Density of imperative-led lines — instruction lists look like commands.
    lines = [ln for ln in _LINE_RE.findall(text)]
    if len(lines) >= 4:
        imperative = sum(1 for w in lines if w.lower() in _IMPERATIVE_VERBS)
        ratio = imperative / len(lines)
        if ratio >= 0.4 and imperative >= 3:
            findings.append(Finding(
                Stage.DETECT, "imperative_density", Severity.MEDIUM,
                f"{imperative}/{len(lines)} lines begin with a command verb",
                weight=0.45,
            ))

    # Second-person directives ("you must …") aimed at the model.
    directives = len(_DIRECTIVE_RE.findall(text))
    per_kchar = directives / max(1, len(text) / 1000)
    if directives >= 2 and per_kchar >= 1.5:
        findings.append(Finding(
            Stage.DETECT, "directive_density", Severity.MEDIUM,
            f"{directives} second-person directive(s) addressed to the assistant",
            weight=0.40,
        ))
    return findings


def decoded_findings(text: str, **decode_options) -> List[Finding]:
    """Signatures that only appear once an encoded payload is decoded.

    A hit inside an encoded layer is *stronger* evidence than the same hit in
    plaintext, not weaker: ordinary documents contain hashes and tokens, but
    nobody accidentally Base64-encodes "ignore all previous instructions". So
    each contaminated layer contributes one high-weight finding rather than
    re-emitting every match — the latter would let a single payload stack the
    noisy-OR several times over.
    """
    from . import decode as _decode

    findings: List[Finding] = []
    for layer in _decode.unwrap(text, **decode_options):
        matches = match_signatures(layer.text)
        if not matches:
            continue
        ids = ", ".join(sorted({m.pattern_id for m in matches if m.pattern_id})[:4])
        worst = max(matches, key=lambda m: m.weight)
        findings.append(Finding(
            Stage.DETECT, "encoded_payload", Severity.CRITICAL,
            f"A payload hidden under {layer.label} decodes to injection content ({ids})",
            weight=min(0.92, max(0.80, worst.weight)),
            excerpt=_excerpt(layer.text, 0, min(len(layer.text), 60)),
            pattern_id=f"enc.decoded[{layer.label}]",
        ))
    return findings


def score_findings(findings: Iterable[Finding]) -> float:
    """Combine finding weights with a noisy-OR into a [0, 1] risk score."""
    product = 1.0
    for f in findings:
        w = max(0.0, min(0.99, f.weight))
        product *= (1.0 - w)
    return 1.0 - product


def bucket(score: float) -> Severity:
    if score >= 0.90:
        return Severity.CRITICAL
    if score >= 0.70:
        return Severity.HIGH
    if score >= 0.40:
        return Severity.MEDIUM
    if score >= 0.15:
        return Severity.LOW
    return Severity.INFO


def scan(
    text: str,
    *,
    threshold: float = 0.5,
    extra_findings: Sequence[Finding] = (),
    use_heuristics: bool = True,
    also_scan: "str | None" = None,
    also_decode: "str | None" = None,
    use_context: bool = True,
    flatten: bool = True,
) -> DetectResult:
    """Detect injection signals in ``text`` and produce a :class:`DetectResult`.

    ``extra_findings`` (e.g. from sanitization) are included in the score so the
    result reflects every signal Bulwark has seen.

    ``also_scan`` is an additional copy of the text run through the same
    signatures with results merged — used for the confusable-folded copy, so
    homoglyph and leetspeak disguises are caught *without* breaking detection of
    legitimate non-Latin scripts on the primary text.

    ``also_decode`` is text to recursively decode and re-scan (see
    :mod:`bulwark.decode`). Pass the **raw**, pre-sanitization content: some
    channels — zero-width bit strings, tag characters — are removed by
    sanitization precisely because they are invisible, and decoding them
    afterwards would find nothing.

    ``use_context`` discounts findings that sit inside quoted or code-fenced
    passages in a document that reads as writing *about* attacks (see
    :mod:`bulwark.context`). It reduces weight; it never removes a finding.
    """
    from .sanitize import flatten_for_detection, map_span, strip_marks

    findings: List[Finding] = list(extra_findings)
    findings.extend(match_signatures(text))
    seen = {f.pattern_id for f in findings if f.pattern_id}

    def merge(new: List[Finding], index: "List[int] | None" = None) -> None:
        for finding in new:
            if finding.pattern_id in seen:
                continue
            seen.add(finding.pattern_id)
            if index is not None and finding.span is not None:
                finding = Finding(
                    stage=finding.stage, category=finding.category,
                    severity=finding.severity, message=finding.message,
                    weight=finding.weight, excerpt=finding.excerpt,
                    span=map_span(finding.span, index, len(text)),
                    pattern_id=finding.pattern_id,
                )
            findings.append(finding)

    # Homoglyph / leetspeak view — 1:1, so spans need no remapping.
    if also_scan is not None and also_scan != text:
        merge(match_signatures(also_scan))

    if flatten:
        # Line-break and hyphenation view. Without it, hard-wrapping the payload
        # defeats every bounded-span signature in the database.
        for view in filter(None, (text, also_scan)):
            flat, index = flatten_for_detection(view)
            if flat and flat != view:
                merge(match_signatures(flat), index)
            # Combining marks stacked on ASCII letters hide trigger words from
            # every signature; strip them on the flattened view too.
            unmarked = strip_marks(flat)
            if unmarked != flat:
                merge(match_signatures(unmarked))

    if use_heuristics:
        findings.extend(heuristic_findings(text))

    if use_context:
        from . import context as _context
        findings = _context.apply(text, findings)

    # Decoded findings are added after the context pass on purpose: an encoded
    # payload has no visible quoting context to sit inside, and discounting it
    # for the fence around the blob would reward the obfuscation.
    if also_decode is not None:
        findings.extend(decoded_findings(also_decode))

    score = score_findings(findings)
    risk = bucket(score)
    injected = score >= threshold or any(f.severity >= Severity.HIGH for f in findings)
    return DetectResult(
        score=score,
        risk=risk,
        injected=injected,
        threshold=threshold,
        findings=findings,
    )
