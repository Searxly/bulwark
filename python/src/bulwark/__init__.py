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

from .detect import bucket, scan as _scan, score_findings
from .guard import Bulwark, BulwarkConfig, PreparedRequest
from .prompt import PromptContext, build_messages
from .sanitize import (
    collapse_spaced_letters,
    fold_confusables,
    fold_for_detection,
    fold_leet,
)
from .patterns import SIGNATURES, Signature, make_signature
from .sanitize import sanitize as sanitize_text
from .spotlight import spotlight
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

__version__ = "0.4.0"

__all__ = [
    "Bulwark",
    "BulwarkConfig",
    "PreparedRequest",
    "scan",
    "sanitize_text",
    "fold_confusables",
    "fold_leet",
    "collapse_spaced_letters",
    "fold_for_detection",
    "spotlight",
    "build_messages",
    "validate_output",
    "score_findings",
    "bucket",
    "make_signature",
    "Signature",
    "SIGNATURES",
    "PromptContext",
    "DetectResult",
    "Finding",
    "GuardResult",
    "SanitizeResult",
    "SpotlightResult",
    "ValidationResult",
    "Severity",
    "Stage",
    "__version__",
]


def scan(text: str, *, threshold: float = 0.5, extra_signatures=()) -> DetectResult:
    """Sanitize then detect injection in ``text`` — convenience wrapper, no model call.

    Detection runs on a de-obfuscated copy (spaced-out letters joined, cross-script
    homoglyphs and leetspeak folded) and decodes embedded Base64 payloads, so the
    common keyword-evasion tricks are caught. Pass ``extra_signatures`` (from
    :func:`make_signature`) to add custom patterns.
    """
    result = sanitize_text(text)
    return _scan(
        result.text,
        threshold=threshold,
        extra_findings=result.findings,
        also_scan=fold_for_detection(result.text),
        extra_signatures=extra_signatures,
    )
