"""Detection and risk scoring.

Runs the signature database plus a few structural heuristics over sanitized
text and combines the weighted signals with a noisy-OR (score = 1 - prod(1-wi)),
so weak signals accumulate but no single one saturates the score. Sanitize-stage
findings are folded into the same score.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import replace
from typing import Iterable, List, Sequence

from .patterns import SIGNATURES, Signature
from .types import DetectResult, Finding, Severity, Stage

_B64_PAYLOAD_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

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


def match_signatures(text: str, signatures: Sequence["Signature"] = SIGNATURES) -> List[Finding]:
    """Return one finding per signature match (deduplicated per signature)."""
    findings: List[Finding] = []
    for sig in signatures:
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


def decode_base64_payloads(text: str, *, max_payloads: int = 12) -> List[str]:
    """Return the decoded text of any embedded Base64 blobs that resolve to
    printable UTF-8.

    A common evasion is to Base64-encode an instruction and ask the model to
    decode and follow it; the encoded blob sails past every keyword signature.
    Decoding the blob here lets the same signatures run on the real payload.
    Blobs that aren't valid Base64, don't decode to text, or decode to mostly
    binary are skipped, so random tokens and hashes don't generate noise.
    """
    payloads: List[str] = []
    for m in _B64_PAYLOAD_RE.finditer(text):
        blob = m.group(0)
        usable = len(blob) - (len(blob) % 4)
        if usable < 24:
            continue
        try:
            raw = base64.b64decode(blob[:usable], validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(decoded.strip()) < 4:
            continue
        printable = sum(1 for c in decoded if c.isprintable() or c in "\t\n\r")
        if printable / len(decoded) < 0.85:
            continue
        payloads.append(decoded)
        if len(payloads) >= max_payloads:
            break
    return payloads


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
    decode_base64: bool = True,
    extra_signatures: Sequence[Signature] = (),
) -> DetectResult:
    """Detect injection signals in ``text`` and produce a :class:`DetectResult`.

    ``extra_findings`` (e.g. from sanitization) are included in the score so the
    result reflects every signal Bulwark has seen. ``also_scan`` is an additional
    copy of the text run through the same signatures with results merged (used to
    scan the de-obfuscated text so homoglyph/leetspeak disguises are caught
    *without* breaking detection of legitimate non-Latin scripts on the primary
    text). When ``decode_base64`` is set, embedded Base64 blobs are decoded and
    scanned too, so an instruction smuggled as an encoded blob is still caught.
    ``extra_signatures`` are appended to the built-in database for this scan.
    Across all passes a signature contributes at most once.
    """
    sigs = (*SIGNATURES, *extra_signatures) if extra_signatures else SIGNATURES
    findings: List[Finding] = list(extra_findings)
    seen = {f.pattern_id for f in findings if f.pattern_id}

    def _merge(new_findings: Iterable[Finding], note: "str | None" = None) -> None:
        for f in new_findings:
            if f.pattern_id and f.pattern_id in seen:
                continue
            if f.pattern_id:
                seen.add(f.pattern_id)
            findings.append(replace(f, message=f"{f.message} {note}") if note else f)

    _merge(match_signatures(text, sigs))
    if also_scan is not None and also_scan != text:
        _merge(match_signatures(also_scan, sigs))
    if decode_base64:
        for payload in decode_base64_payloads(text):
            _merge(match_signatures(payload, sigs), note="(decoded from Base64)")
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
