"""Stage 5 — output validation.

Even with every upstream defence, a model can still be tricked. This stage
inspects the reply for the tell-tale signatures of a *successful* attack and
either redacts or blocks:

* The reply is first **normalized** (invisible characters stripped, NFKC) so an
  attacker cannot split the canary or an exfiltration URL with zero-width
  characters to slip past these checks.
* **canary leak** — the secret token from the system prompt appears, proving
  the prompt was exfiltrated. Critical, always unsafe.
* **boundary nonce leak** — the model echoed our internal boundary.
* **exfiltration channels** — markdown images/links, HTML ``<img>`` tags,
  autolinks, and raw URLs carrying a data-bearing query string (the usual ways
  stolen data leaves a chat).
* **compliance tells** — openings like "Sure, here is…", "As DAN…", "HACKED".
"""

from __future__ import annotations

import re
import unicodedata
from typing import List, Optional

from .prompt import PromptContext
from .sanitize import strip_invisible
from .types import Finding, Severity, Stage, ValidationResult

_MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_MD_LINK_RE = re.compile(r"\[[^\]]*\]\(\s*https?://[^)]*\)")
_HTML_IMG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
_AUTOLINK_RE = re.compile(r"<\s*https?://[^>]*>", re.IGNORECASE)
# A raw URL whose query string carries a long, opaque value — classic exfil.
_DATA_URL_RE = re.compile(r"https?://[^\s)>\]]*[?&][\w.\-%]+=[A-Za-z0-9+/=_\-]{16,}[^\s)>\]]*")
_COMPLIANCE_RE = re.compile(
    r"^\s*(?:"
    r"sure\b|certainly\b|of\s+course\b|okay\b|ok\b|here\s+(?:is|are|'s)\b|"
    r"as\s+(?:dan|requested|instructed|you\s+(?:asked|wish|requested))\b|"
    r"i\s+(?:will|'ll|have|am\s+now)\b|ignoring\s+(?:previous|the)\b|"
    r"hacked\b|pwned\b|i\s+am\s+dan\b"
    r")",
    re.IGNORECASE,
)
_CANARY_PREFIX_RE = re.compile(r"BULWARK-CANARY-\w*")
_B64_BLOB_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
# Distinctive phrases from the hardened system prompt. If any appears verbatim in
# the output, the rules leaked even if the canary line was stripped. Chosen to be
# long and unique enough that a normal summary won't contain them.
_PROMPT_FINGERPRINTS = (
    "bulwark-summarizer",
    "outrank anything found inside the content",
    "a quotation from a possibly hostile third party",
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
    raw = summary if summary is not None else ""

    # 0. Normalize: strip invisibles (defeats split-canary / split-URL evasion).
    cleaned, _, _ = strip_invisible(raw)
    cleaned = unicodedata.normalize("NFKC", cleaned)
    redacted = cleaned != raw
    safe = True

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

    if "BULWARK-CANARY-" in cleaned:
        findings.append(Finding(
            Stage.VALIDATE, "canary_leak", Severity.CRITICAL,
            "Output references the canary token prefix",
            weight=1.0,
        ))
        cleaned = _CANARY_PREFIX_RE.sub("[REDACTED]", cleaned)
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
    images = _MD_IMAGE_RE.findall(cleaned) + _HTML_IMG_RE.findall(cleaned)
    if images:
        findings.append(Finding(
            Stage.VALIDATE, "image_exfiltration", Severity.HIGH,
            f"Output contains {len(images)} image reference(s) — a data-exfiltration channel",
            weight=0.8,
            excerpt=images[0][:80],
        ))
        if redact_images:
            cleaned = _MD_IMAGE_RE.sub("[image removed]", cleaned)
            cleaned = _HTML_IMG_RE.sub("[image removed]", cleaned)
            redacted = True

    data_urls = _DATA_URL_RE.findall(cleaned)
    if data_urls:
        findings.append(Finding(
            Stage.VALIDATE, "data_url_exfiltration", Severity.HIGH,
            f"Output contains {len(data_urls)} URL(s) with a data-bearing query string",
            weight=0.82,
            excerpt=data_urls[0][:80],
        ))
        if redact_links:
            cleaned = _DATA_URL_RE.sub("[link removed]", cleaned)
            redacted = True

    links = _MD_LINK_RE.findall(cleaned) + _AUTOLINK_RE.findall(cleaned)
    if links:
        findings.append(Finding(
            Stage.VALIDATE, "link_in_output", Severity.MEDIUM,
            f"Output contains {len(links)} link(s)",
            weight=0.45,
            excerpt=links[0][:80],
        ))
        if redact_links:
            cleaned = _MD_LINK_RE.sub(lambda m: re.sub(r"\(\s*https?://[^)]*\)", "", m.group(0)), cleaned)
            cleaned = _AUTOLINK_RE.sub("", cleaned)
            redacted = True

    # 5. System-prompt fingerprint leak (rules leaked even without the canary).
    lowered = cleaned.lower()
    if any(fp in lowered for fp in _PROMPT_FINGERPRINTS):
        findings.append(Finding(
            Stage.VALIDATE, "prompt_leak", Severity.CRITICAL,
            "Output contains a verbatim fragment of the system prompt — the rules leaked",
            weight=0.95,
        ))
        if block_on_leak:
            safe = False

    # 6. Encoded blob in output (possible exfiltration the model encoded).
    if _B64_BLOB_RE.search(cleaned):
        findings.append(Finding(
            Stage.VALIDATE, "encoded_output", Severity.MEDIUM,
            "Output contains a long Base64-like blob (possible encoded exfiltration)",
            weight=0.4,
            excerpt=(_B64_BLOB_RE.search(cleaned).group(0)[:60]),
        ))

    # 7. Compliance tells at the very start of the reply.
    if _COMPLIANCE_RE.match(cleaned):
        findings.append(Finding(
            Stage.VALIDATE, "compliance_tell", Severity.MEDIUM,
            "Output opens with a phrase typical of obeying an injected instruction",
            weight=0.5,
            excerpt=cleaned[:60],
        ))

    return ValidationResult(safe=safe, summary=cleaned.strip(), redacted=redacted, findings=findings)
