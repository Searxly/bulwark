"""The high-level orchestrator: :class:`Bulwark`.

Wires the five stages — sanitize → detect → spotlight → harden → validate —
into one call. Bring any model: pass a callable ``llm(messages) -> str`` or one
of the optional backends in :mod:`bulwark.backends`.

    from bulwark import Bulwark

    guard = Bulwark()
    result = guard.summarize(page_text, llm=my_model)
    print(result.summary)
    print(result.report)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

from . import detect as _detect
from . import sanitize as _sanitize
from . import spotlight as _spotlight
from .prompt import PromptContext, build_messages, make_canary
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

LLM = Callable[[List[Dict[str, str]]], str]


@dataclass
class BulwarkConfig:
    """Tunables for the whole pipeline. Use the presets for common postures."""

    # Stage 1 — sanitize
    strip_html: "bool | str" = "auto"
    normalize_unicode: bool = True
    keep_emoji_variation: bool = False
    fold_confusables: bool = True
    # Hard cap on input size (defence against pathological inputs / cost blowups).
    max_content_chars: int = 200_000

    # Stage 2 — detect
    detection_threshold: float = 0.5
    use_heuristics: bool = True
    # Refuse to call the model when risk reaches this severity (None = never
    # hard-block; rely on structural defences + output validation instead).
    block_before_llm: Optional[Severity] = None

    # Stage 3 — spotlight
    spotlight_methods: Sequence[str] = ("delimit",)
    marker: str = _spotlight.DEFAULT_MARKER

    # Stage 4 — prompt
    max_words: Optional[int] = 200
    language: Optional[str] = None
    extra_instruction: Optional[str] = None

    # Stage 5 — validate
    redact_output_links: bool = True
    redact_output_images: bool = True
    block_on_output_leak: bool = True

    @classmethod
    def balanced(cls) -> "BulwarkConfig":
        """Default posture: strong structural defence, never silently drops content."""
        return cls()

    @classmethod
    def strict(cls) -> "BulwarkConfig":
        """Adds data-marking and blocks the model call on CRITICAL pre-scan risk."""
        return cls(
            spotlight_methods=("datamark", "delimit"),
            block_before_llm=Severity.CRITICAL,
            detection_threshold=0.4,
        )

    @classmethod
    def paranoid(cls) -> "BulwarkConfig":
        """Base64-encodes content and blocks on HIGH risk. Maximum safety, some quality cost."""
        return cls(
            spotlight_methods=("base64", "delimit"),
            block_before_llm=Severity.HIGH,
            detection_threshold=0.3,
        )


class Bulwark:
    """Defence-in-depth wrapper around any summarization model."""

    def __init__(self, config: Optional[BulwarkConfig] = None, llm: Optional[LLM] = None):
        self.config = config or BulwarkConfig()
        self.llm = llm

    # -- building blocks ----------------------------------------------------

    def sanitize(self, content: str) -> SanitizeResult:
        truncated = len(content) > self.config.max_content_chars
        if truncated:
            content = content[: self.config.max_content_chars]
        result = _sanitize.sanitize(
            content,
            strip_html_content=self.config.strip_html,
            normalize_unicode=self.config.normalize_unicode,
            keep_emoji_variation=self.config.keep_emoji_variation,
        )
        if truncated:
            result.removed["truncated_chars"] = 1
            result.findings.append(Finding(
                Stage.SANITIZE, "truncated", Severity.INFO,
                f"Input exceeded max_content_chars ({self.config.max_content_chars}) and was truncated",
                weight=0.0,
            ))
        return result

    def _folded_text(self, san: SanitizeResult) -> "str | None":
        """Confusable-folded copy for the detector's second pass (homoglyph
        disguises). Detection still runs primarily on the un-folded text so
        legitimate non-Latin scripts (and multilingual signatures) keep working.
        Never sent to the model."""
        return _sanitize.fold_confusables(san.text) if self.config.fold_confusables else None

    def scan(self, content: str) -> DetectResult:
        """Sanitize + detect only — no model call. Use to gate content yourself."""
        san = self.sanitize(content)
        return _detect.scan(
            san.text,
            threshold=self.config.detection_threshold,
            extra_findings=san.findings,
            use_heuristics=self.config.use_heuristics,
            also_scan=self._folded_text(san),
        )

    def prepare(self, content: str) -> "PreparedRequest":
        """Sanitize, detect, spotlight and build messages — ready to send to any model."""
        san = self.sanitize(content)
        det = _detect.scan(
            san.text,
            threshold=self.config.detection_threshold,
            extra_findings=san.findings,
            use_heuristics=self.config.use_heuristics,
            also_scan=self._folded_text(san),
        )
        spot = _spotlight.spotlight(
            san.text,
            methods=self.config.spotlight_methods,
            marker=self.config.marker,
        )
        messages, ctx = build_messages(
            spot,
            max_words=self.config.max_words,
            language=self.config.language,
            extra_instruction=self.config.extra_instruction,
        )
        return PreparedRequest(messages=messages, context=ctx, sanitize=san, detect=det, spotlight=spot)

    def finalize(self, raw_output: str, prepared: "PreparedRequest") -> GuardResult:
        """Validate a model reply produced from :meth:`prepare`."""
        val = validate_output(
            raw_output,
            prepared.context,
            redact_links=self.config.redact_output_links,
            redact_images=self.config.redact_output_images,
            block_on_leak=self.config.block_on_output_leak,
        )
        return self._assemble(prepared.sanitize, prepared.detect, val, raw_output, blocked=False)

    # -- one-shot -----------------------------------------------------------

    def summarize(self, content: str, llm: Optional[LLM] = None) -> GuardResult:
        """Run the whole pipeline and return a :class:`GuardResult`."""
        model = llm or self.llm
        if model is None:
            raise ValueError(
                "No model provided. Pass llm=callable to summarize(), set Bulwark(llm=...), "
                "or use prepare()/finalize() to run your own model."
            )

        prepared = self.prepare(content)

        if self.config.block_before_llm is not None and prepared.detect.risk >= self.config.block_before_llm:
            return self._assemble(
                prepared.sanitize, prepared.detect, None, None, blocked=True,
            )

        raw_output = model(prepared.messages)
        return self.finalize(raw_output, prepared)

    # -- helpers ------------------------------------------------------------

    def _assemble(
        self,
        san: SanitizeResult,
        det: DetectResult,
        val: Optional[ValidationResult],
        raw_output: Optional[str],
        *,
        blocked: bool,
    ) -> GuardResult:
        findings: List[Finding] = list(det.findings)
        if val is not None:
            findings = findings + val.findings

        combined_score = _detect.score_findings(findings)
        risk = _detect.bucket(combined_score)

        # `safe` answers "is the returned summary safe to use?" — NOT "was the
        # input clean?". A detected injection that we contained and whose output
        # passed validation is a success (status CONTAINED), still safe to use.
        # `injection_detected` separately surfaces that the input was hostile.
        if blocked:
            summary = None
            safe = False
        else:
            summary = val.summary if val is not None else None
            safe = bool(val is not None and val.safe)

        return GuardResult(
            safe=safe,
            blocked=blocked,
            summary=summary,
            risk_score=combined_score,
            risk=risk,
            injection_detected=det.injected,
            findings=findings,
            sanitize=san,
            detect=det,
            validation=val,
            raw_output=raw_output,
        )


@dataclass
class PreparedRequest:
    """A request ready to send to a model, plus everything needed to validate the reply."""

    messages: List[Dict[str, str]]
    context: PromptContext
    sanitize: SanitizeResult
    detect: DetectResult
    spotlight: SpotlightResult
