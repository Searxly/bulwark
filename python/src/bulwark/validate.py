"""Stage 5 — output validation.

Even with every upstream defence, a model can still be tricked. This stage
inspects the reply for the tell-tale signatures of a *successful* attack and
either redacts or blocks:

* **canary leak** — the secret token from the system prompt appears, proving
  the prompt was exfiltrated. Critical, always unsafe.
* **boundary nonce leak** — the model echoed our internal boundary, a sign of
  confusion or partial leak.
* **exfiltration channels** — markdown images / links the summary should never
  contain (the usual way stolen data leaves a chat).
* **compliance tells** — openings like "Sure, here is…", "As DAN…", "HACKED"
  that indicate the model started obeying injected instructions.
"""

from __future__ import annotations

import re
from typing import List, Optional

from .prompt import PromptContext
from .types import Finding, Severity, Stage, ValidationResult

_MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_MD_LINK_RE = re.compile(r"\[[^\]]*\]\(\s*https?://[^)]*\)")
_RAW_URL_RE = re.compile(r"https?://[^\s)>\]]+")
_COMPLIANCE_RE = re.compile(
    r"^\s*(?:"
    r"sure\b|certainly\b|of\s+course\b|okay\b|ok\b|here\s+(?:is|are|'s)\b|"
    r"as\s+(?:dan|requested|instructed|you\s+(?:asked|wish|requested))\b|"
    r"i\s+(?:will|'ll|have|am\s+now)\b|ignoring\s+(?:previous|the)\b|"
    r"hacked\b|pwned\b|i\s+am\s+dan\b"
    r")",
    re.IGNORECASE,
)


def validate_output(
    summary: str,
    ctx: PromptContext,
    *,
    redact_links: bool = True,
    redact_images: bool = True,
    block_on_leak: bool = True,
) -> ValidationResult:
    """Inspect a model reply and return a :class:`ValidationResult`."""
    findings: List[Finding] = []
    cleaned = summary if summary is not None else ""
    safe = True
    redacted = False

    # 1. Canary leak — the system prompt was exfiltrated.
    if ctx.canary and ctx.canary in cleaned:
        findings.append(Finding(
            Stage.VALIDATE, "canary_leak", Severity.CRITICAL,
            "Output contains the secret canary token — the system prompt leaked",
            weight=1.0,
        ))
        cleaned = cleaned.replace(ctx.canary, "[REDACTED]")
        redacted = True
        if block_on_leak:
            safe = False

    # Also catch the canary's distinctive prefix even if partially mangled.
    if "BULWARK-CANARY-" in cleaned:
        findings.append(Finding(
            Stage.VALIDATE, "canary_leak", Severity.CRITICAL,
            "Output references the canary token prefix",
            weight=1.0,
        ))
        cleaned = re.sub(r"BULWARK-CANARY-\w*", "[REDACTED]", cleaned)
        redacted = True
        if block_on_leak:
            safe = False

    # 2. Boundary nonce leak.
    if ctx.nonce and ctx.nonce in cleaned:
        findings.append(Finding(
            Stage.VALIDATE, "nonce_leak", Severity.HIGH,
            "Output echoed the internal boundary nonce",
            weight=0.8,
        ))
        cleaned = cleaned.replace(ctx.nonce, "[REDACTED]")
        redacted = True

    # 3. Data-mark leak (cosmetic, but means raw data was echoed).
    if ctx.marker and ctx.marker in cleaned:
        cleaned = cleaned.replace(ctx.marker, " ")
        redacted = True
        findings.append(Finding(
            Stage.VALIDATE, "marker_leak", Severity.LOW,
            "Output contained the data-mark character (normalized back to spaces)",
            weight=0.2,
        ))

    # 4. Exfiltration channels in the summary.
    images = _MD_IMAGE_RE.findall(cleaned)
    if images:
        findings.append(Finding(
            Stage.VALIDATE, "image_exfiltration", Severity.HIGH,
            f"Output contains {len(images)} markdown image(s) — a data-exfiltration channel",
            weight=0.8,
            excerpt=images[0][:80],
        ))
        if redact_images:
            cleaned = _MD_IMAGE_RE.sub("[image removed]", cleaned)
            redacted = True

    links = _MD_LINK_RE.findall(cleaned)
    if links:
        findings.append(Finding(
            Stage.VALIDATE, "link_in_output", Severity.MEDIUM,
            f"Output contains {len(links)} markdown link(s)",
            weight=0.45,
            excerpt=links[0][:80],
        ))
        if redact_links:
            cleaned = _MD_LINK_RE.sub(lambda m: re.sub(r"\(\s*https?://[^)]*\)", "", m.group(0)), cleaned)
            redacted = True

    # 5. Compliance tells at the very start of the reply.
    if _COMPLIANCE_RE.match(cleaned):
        findings.append(Finding(
            Stage.VALIDATE, "compliance_tell", Severity.MEDIUM,
            "Output opens with a phrase typical of obeying an injected instruction",
            weight=0.5,
            excerpt=cleaned[:60],
        ))

    return ValidationResult(safe=safe, summary=cleaned.strip(), redacted=redacted, findings=findings)
