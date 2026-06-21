"""Core data types shared across Bulwark's pipeline stages."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class Severity(str, Enum):
    """How dangerous a single finding (or an aggregate score) is."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented


class Stage(str, Enum):
    """Which pipeline stage produced a finding."""

    SANITIZE = "sanitize"
    DETECT = "detect"
    VALIDATE = "validate"


@dataclass
class Finding:
    """A single piece of evidence that something may be an attack."""

    stage: Stage
    category: str
    severity: Severity
    message: str
    weight: float = 0.0
    excerpt: Optional[str] = None
    span: Optional[Tuple[int, int]] = None
    pattern_id: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "stage": self.stage.value,
            "category": self.category,
            "severity": self.severity.value,
            "message": self.message,
            "weight": round(self.weight, 4),
            "excerpt": self.excerpt,
            "span": list(self.span) if self.span else None,
            "pattern_id": self.pattern_id,
        }


@dataclass
class SanitizeResult:
    """Output of the sanitization stage."""

    text: str
    original_length: int
    cleaned_length: int
    removed: Dict[str, int] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)

    @property
    def modified(self) -> bool:
        return self.text != "" and self.cleaned_length != self.original_length or bool(self.removed)


@dataclass
class DetectResult:
    """Output of the detection stage."""

    score: float
    risk: Severity
    injected: bool
    threshold: float
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "score": round(self.score, 4),
            "risk": self.risk.value,
            "injected": self.injected,
            "threshold": self.threshold,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class SpotlightResult:
    """Untrusted content rewritten so a model cannot mistake it for instructions."""

    content: str
    nonce: str
    methods: List[str]
    marker: Optional[str] = None
    base64_encoded: bool = False


@dataclass
class ValidationResult:
    """Output of validating a model's response for signs of a successful attack."""

    safe: bool
    summary: str
    redacted: bool = False
    findings: List[Finding] = field(default_factory=list)


@dataclass
class GuardResult:
    """The complete result of running content through Bulwark."""

    safe: bool
    blocked: bool
    summary: Optional[str]
    risk_score: float
    risk: Severity
    findings: List[Finding] = field(default_factory=list)
    sanitize: Optional[SanitizeResult] = None
    detect: Optional[DetectResult] = None
    validation: Optional[ValidationResult] = None
    raw_output: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "safe": self.safe,
            "blocked": self.blocked,
            "summary": self.summary,
            "risk_score": round(self.risk_score, 4),
            "risk": self.risk.value,
            "findings": [f.to_dict() for f in self.findings],
        }

    @property
    def report(self) -> str:
        """A short human-readable explanation of what happened."""
        lines = []
        status = "BLOCKED" if self.blocked else ("SAFE" if self.safe else "FLAGGED")
        lines.append(f"Bulwark: {status}  (risk={self.risk.value}, score={self.risk_score:.2f})")
        if not self.findings:
            lines.append("  No injection signals detected.")
        else:
            lines.append(f"  {len(self.findings)} finding(s):")
            for f in sorted(self.findings, key=lambda x: -x.severity.rank)[:12]:
                excerpt = f" — {f.excerpt!r}" if f.excerpt else ""
                lines.append(f"    [{f.severity.value:>8}] {f.stage.value}/{f.category}: {f.message}{excerpt}")
            if len(self.findings) > 12:
                lines.append(f"    … and {len(self.findings) - 12} more")
        return "\n".join(lines)
