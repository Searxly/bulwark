"""Bulwark — an open-source safeguard against prompt injection in AI summarization.

Quick start::

    from bulwark import Bulwark

    guard = Bulwark()
    result = guard.summarize(untrusted_web_page, llm=my_model)  # my_model(messages) -> str
    print(result.summary)   # cleaned, validated summary (or None if blocked)
    print(result.report)    # human-readable explanation of what was caught

Just want detection, no model?::

    from bulwark import scan
    verdict = scan(some_text)
    if verdict.injected:
        ...

Everything is composable — see :mod:`bulwark.sanitize`, :mod:`bulwark.detect`,
:mod:`bulwark.spotlight`, :mod:`bulwark.prompt`, :mod:`bulwark.validate`.
"""

from __future__ import annotations

from .context import profile as context_profile
from .decode import unwrap as decode_layers
from .detect import bucket, decoded_findings, scan as _scan, score_findings
from .grounding import GroundingReport, check_grounding
from .guard import Bulwark, BulwarkConfig, PreparedRequest
from .prompt import PromptContext, build_messages
from .rampart import Entity as PIIEntity, Redaction, redact, rehydrate
from .sanitize import fold_confusables, fold_detection, fold_leet
from .sanitize import sanitize as sanitize_text
from .segment import Segment, SegmentReport, analyze_segments, neutralize
from .session import Session, SessionVerdict
from .spotlight import spotlight
from .toolguard import (
    CallAssessment,
    OutputAssessment,
    TaintPolicy,
    ToolGuard,
    ToolGuardConfig,
    ToolRisk,
    Verdict,
)
from .tripwire import Tripwire, make_tripwire
from .types import (
    DetectResult,
    Finding,
    GuardResult,
    SanitizeResult,
    Severity,
    SpotlightResult,
    Stage,
    ValidationResult,
)
from .validate import validate_output

__version__ = "1.0.0"

__all__ = [
    "Bulwark",
    "BulwarkConfig",
    "PreparedRequest",
    "scan",
    "sanitize_text",
    "fold_confusables",
    "fold_leet",
    "fold_detection",
    "spotlight",
    "build_messages",
    "validate_output",
    "score_findings",
    "bucket",
    "PromptContext",
    "DetectResult",
    "Finding",
    "GuardResult",
    "SanitizeResult",
    "SpotlightResult",
    "ValidationResult",
    "Severity",
    "Stage",
    # decode / context / grounding / segmentation
    "decode_layers",
    "decoded_findings",
    "context_profile",
    "check_grounding",
    "GroundingReport",
    "analyze_segments",
    "neutralize",
    "Segment",
    "SegmentReport",
    # tripwire
    "make_tripwire",
    "Tripwire",
    # cross-document sessions
    "Session",
    "SessionVerdict",
    # agentic tool safeguards
    "ToolGuard",
    "ToolGuardConfig",
    "ToolRisk",
    "Verdict",
    "TaintPolicy",
    "CallAssessment",
    "OutputAssessment",
    # sensitive-value redaction
    "redact",
    "rehydrate",
    "Redaction",
    "PIIEntity",
    "__version__",
]


def scan(
    text: str,
    *,
    threshold: float = 0.5,
    decode_encoded: bool = True,
    use_context: bool = True,
) -> DetectResult:
    """Sanitize then detect injection in ``text`` — convenience wrapper, no model call.

    Runs the full detection stack, not a reduced one: signatures over the
    sanitized text, a folded copy so leetspeak ("1gn0r3") and cross-script
    homoglyph disguises are caught, recursive decoding of encoded payloads over
    the *raw* text, and quoting-context discounting.
    """
    result = sanitize_text(text)
    return _scan(
        result.text,
        threshold=threshold,
        extra_findings=result.findings,
        also_scan=fold_detection(result.text),
        also_decode=text if decode_encoded else None,
        use_context=use_context,
    )
