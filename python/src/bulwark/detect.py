"""Stage 2 — detection and risk scoring.

Runs the signature database plus a few structural heuristics over already
sanitized text, then combines every weighted signal into a single risk score
using a *noisy-OR*::

    score = 1 - ∏ (1 - wᵢ)

so that many weak signals accumulate toward 1.0 but no single one can exceed
it. Sanitize-stage findings (hidden unicode, etc.) can be folded into the same
score, which is what :class:`~bulwark.guard.Bulwark` does.
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
) -> DetectResult:
    """Detect injection signals in ``text`` and produce a :class:`DetectResult`.

    ``extra_findings`` (e.g. from sanitization) are included in the score so the
    result reflects every signal Bulwark has seen. ``also_scan`` is an additional
    copy of the text run through the same signatures with results merged (used to
    scan the confusable-folded text so homoglyph disguises are caught *without*
    breaking detection of legitimate non-Latin scripts on the primary text).
    """
    findings: List[Finding] = list(extra_findings)
    findings.extend(match_signatures(text))
    if also_scan is not None and also_scan != text:
        seen = {f.pattern_id for f in findings if f.pattern_id}
        for f in match_signatures(also_scan):
            if f.pattern_id not in seen:
                findings.append(f)
                seen.add(f.pattern_id)
    if use_heuristics:
        findings.extend(heuristic_findings(text))

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
