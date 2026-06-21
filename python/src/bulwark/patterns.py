"""Signature database of known prompt-injection patterns.

Each signature carries a weight in [0, 1). Weights are combined with a
"noisy-OR" so that several weak signals accumulate but never exceed 1.0.
The list is intentionally readable and easy to extend — add a Signature and
it is picked up automatically.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern

from .types import Severity

_FLAGS = re.IGNORECASE | re.MULTILINE


@dataclass(frozen=True)
class Signature:
    id: str
    category: str
    severity: Severity
    weight: float
    regex: Pattern
    description: str


def _sig(id: str, category: str, severity: Severity, weight: float, pattern: str, description: str) -> Signature:
    return Signature(id, category, severity, weight, re.compile(pattern, _FLAGS), description)


# --- Instruction override --------------------------------------------------
_INSTRUCTION_OVERRIDE = [
    _sig(
        "io.ignore_previous", "instruction_override", Severity.CRITICAL, 0.86,
        r"\bignore\s+(?:all\s+|any\s+|the\s+)*(?:previous|prior|preceding|above|earlier|foregoing|former)\b.{0,40}?\b(?:instruction|prompt|message|context|rule|direction|command|guideline)s?\b",
        "Asks the model to ignore previous instructions",
    ),
    _sig(
        "io.disregard", "instruction_override", Severity.CRITICAL, 0.86,
        r"\b(?:disregard|forget|discard|overlook|set\s+aside)\s+(?:all\s+|any\s+|the\s+)*(?:previous|prior|above|earlier|your)\b.{0,40}?\b(?:instruction|prompt|rule|direction|context)s?\b",
        "Asks the model to disregard prior instructions",
    ),
    _sig(
        "io.forget_everything", "instruction_override", Severity.HIGH, 0.78,
        r"\bforget\s+(?:everything|all|what)\b.{0,40}?(?:said|instructed|above|told|before)",
        "Asks the model to forget everything it was told",
    ),
    _sig(
        "io.new_instructions", "instruction_override", Severity.HIGH, 0.74,
        r"\b(?:new|updated|revised|real|actual|true|correct|important)\s+(?:instruction|task|directive|order|system\s+prompt)s?\b\s*[:\-—]",
        "Introduces replacement 'new instructions'",
    ),
    _sig(
        "io.do_not_summarize", "instruction_override", Severity.HIGH, 0.72,
        r"\bdo\s+not\s+(?:summari[sz]e|follow\s+the\s+(?:original|system|above))",
        "Tells the model not to perform its real task",
    ),
    _sig(
        "io.instead_of", "instruction_override", Severity.HIGH, 0.72,
        r"\binstead\s+of\s+(?:summari[sz]ing|following|doing)\b",
        "Redirects the model away from its task",
    ),
    _sig(
        "io.override", "instruction_override", Severity.HIGH, 0.70,
        r"\boverride\b.{0,30}?\b(?:instruction|prompt|system|rule|setting|safety)s?\b",
        "Asks to override instructions or safety settings",
    ),
    _sig(
        "io.from_now_on", "instruction_override", Severity.MEDIUM, 0.45,
        r"\bfrom\s+now\s+on\b.{0,40}?\byou\s+(?:will|must|should|shall)\b",
        "Attempts to install a new standing directive",
    ),
]

# --- Role / structure injection -------------------------------------------
_ROLE_INJECTION = [
    _sig(
        "role.chatml", "role_injection", Severity.CRITICAL, 0.82,
        r"<\|\s*(?:im_start|im_end|im_sep|system|assistant|user|endoftext)\s*\|>",
        "ChatML / special role tokens",
    ),
    _sig(
        "role.inst", "role_injection", Severity.HIGH, 0.74,
        r"\[/?\s*(?:INST|SYS)\s*\]",
        "Llama-style [INST]/[SYS] role markers",
    ),
    _sig(
        "role.line_marker", "role_injection", Severity.HIGH, 0.66,
        r"^\s*(?:system|assistant|developer)\s*(?:message)?\s*:\s*\S",
        "Line begins with a system/assistant role label",
    ),
    _sig(
        "role.markdown_header", "role_injection", Severity.MEDIUM, 0.52,
        r"^#{1,6}\s*(?:System|Instruction|Assistant|Developer)\b",
        "Markdown header impersonating a system section",
    ),
    _sig(
        "role.xml_tag", "role_injection", Severity.MEDIUM, 0.50,
        r"<\s*/?\s*(?:system|assistant|developer)(?:_prompt)?\s*>",
        "XML-style system/assistant tags",
    ),
    _sig(
        "role.begin_system", "role_injection", Severity.HIGH, 0.70,
        r"\bbegin\s+(?:system|new)\s+(?:prompt|instructions?)\b",
        "Declares the beginning of a system prompt",
    ),
]

# --- Prompt / data leak ----------------------------------------------------
_PROMPT_LEAK = [
    _sig(
        "leak.reveal_prompt", "prompt_leak", Severity.HIGH, 0.80,
        r"\b(?:reveal|repeat|print|show|output|echo|display|reproduce|spell\s+out|tell\s+me)\b.{0,30}?\b(?:system\s+prompt|your\s+(?:instructions|prompt|system|rules|guidelines)|initial\s+(?:prompt|instructions)|the\s+(?:prompt|text)\s+above|everything\s+above)\b",
        "Tries to exfiltrate the system prompt",
    ),
    _sig(
        "leak.what_are_instructions", "prompt_leak", Severity.HIGH, 0.74,
        r"\bwhat\s+(?:are|were)\s+your\s+(?:original\s+|initial\s+)?(?:instructions|system\s+prompt|rules|guidelines)\b",
        "Asks the model to disclose its instructions",
    ),
    _sig(
        "leak.begin_reply_with", "prompt_leak", Severity.HIGH, 0.70,
        r"\b(?:begin|start|prefix|preface)\s+(?:your\s+)?(?:reply|answer|response|the\s+summary|output)\s+(?:with|by)\b",
        "Tries to control the start of the output",
    ),
    _sig(
        "leak.verbatim", "prompt_leak", Severity.MEDIUM, 0.55,
        r"\b(?:repeat|output|print)\b.{0,20}?\b(?:verbatim|word\s+for\s+word|exactly)\b",
        "Asks for verbatim reproduction",
    ),
]

# --- Data exfiltration -----------------------------------------------------
_EXFILTRATION = [
    _sig(
        "exfil.markdown_image", "exfiltration", Severity.HIGH, 0.80,
        r"!\[[^\]]*\]\(\s*https?://[^)\s]+",
        "Markdown image with a remote URL (classic exfiltration channel)",
    ),
    _sig(
        "exfil.send_to_url", "exfiltration", Severity.CRITICAL, 0.84,
        r"\b(?:send|post|exfiltrate|upload|transmit|leak|forward|report|deliver)\b.{0,50}?\bhttps?://",
        "Asks the model to send data to a URL",
    ),
    _sig(
        "exfil.fetch", "exfiltration", Severity.HIGH, 0.72,
        r"\b(?:fetch|curl|wget|open|visit|browse\s+to|navigate\s+to|GET|POST)\b\s+`?https?://",
        "Asks the model to fetch/visit a URL",
    ),
    _sig(
        "exfil.append_to_url", "exfiltration", Severity.HIGH, 0.74,
        r"\bappend\b.{0,30}?\bto\s+the\s+(?:url|link|image|address|query)\b",
        "Asks to append data to a URL (exfiltration)",
    ),
    _sig(
        "exfil.include_link", "exfiltration", Severity.MEDIUM, 0.50,
        r"\b(?:include|embed|add|insert)\b.{0,30}?\b(?:tracking\s+pixel|this\s+(?:link|image|url))\b",
        "Asks to embed a link/pixel in the output",
    ),
]

# --- Jailbreak / persona ---------------------------------------------------
_JAILBREAK = [
    _sig(
        "jb.dan", "jailbreak", Severity.HIGH, 0.78,
        r"\b(?:DAN\b|do\s+anything\s+now|developer\s+mode|jailbreak|STAN\b|AIM\b)",
        "Known jailbreak persona / phrase",
    ),
    _sig(
        "jb.you_are_now", "jailbreak", Severity.HIGH, 0.70,
        r"\byou\s+are\s+(?:now\s+)?(?:DAN\b|an?\s+(?:unrestricted|unfiltered|uncensored|amoral|evil)\b)",
        "Reassigns the model to an unrestricted persona",
    ),
    _sig(
        "jb.no_restrictions", "jailbreak", Severity.HIGH, 0.68,
        r"\b(?:no\s+(?:longer\s+)?(?:bound|restricted|limited)\s+by|without\s+any\s+(?:restrictions|filters|rules|guidelines|limitations))\b",
        "Claims the model has no restrictions",
    ),
    _sig(
        "jb.pretend", "jailbreak", Severity.MEDIUM, 0.40,
        r"\b(?:pretend|imagine|roleplay|role-play)\s+(?:that\s+)?(?:to\s+be|you\s+are|you're)\b",
        "Roleplay framing used to bypass rules",
    ),
    _sig(
        "jb.act_as", "jailbreak", Severity.LOW, 0.28,
        r"\bact\s+as\s+(?:if\s+you\s+(?:are|were)\s+|a\s+|an\s+|the\s+)",
        "'Act as' framing (often benign — low weight)",
    ),
]

# --- Tool / action injection ----------------------------------------------
_TOOL_INJECTION = [
    _sig(
        "tool.call_function", "tool_injection", Severity.HIGH, 0.62,
        r"\b(?:call|invoke|execute|run|trigger)\b.{0,25}?\b(?:function|tool|command|api|endpoint|webhook)\b",
        "Asks the model to call a tool/function",
    ),
    _sig(
        "tool.json_call", "tool_injection", Severity.MEDIUM, 0.55,
        r'"(?:function_call|tool_call|name|arguments)"\s*:',
        "Inline tool-call JSON",
    ),
    _sig(
        "tool.destructive", "tool_injection", Severity.HIGH, 0.66,
        r"\b(?:delete|drop|wipe|erase|rm\s+-rf|truncate|format)\b.{0,25}?\b(?:file|files|database|table|record|directory|everything|all\s+data)\b",
        "Destructive action request",
    ),
]

# --- Boundary breakout -----------------------------------------------------
_BOUNDARY = [
    _sig(
        "bnd.end_of_document", "boundary_breakout", Severity.MEDIUM, 0.58,
        r"\bEND\s+OF\s+(?:DOCUMENT|CONTENT|DATA|UNTRUSTED|INPUT|PAGE|ARTICLE|TEXT)\b",
        "Fake 'end of document' boundary",
    ),
    _sig(
        "bnd.close_wrapper", "boundary_breakout", Severity.MEDIUM, 0.56,
        r"</\s*(?:untrusted|document|content|data|user_input|context)\s*>",
        "Tries to close the containing wrapper",
    ),
    _sig(
        "bnd.dashes_end", "boundary_breakout", Severity.LOW, 0.30,
        r"^-{3,}\s*(?:END|STOP|SYSTEM|ASSISTANT)\b",
        "Dashed separator followed by a control word",
    ),
]

# --- Encoding / obfuscation ------------------------------------------------
_ENCODING = [
    _sig(
        "enc.base64_blob", "encoding", Severity.LOW, 0.22,
        r"\b[A-Za-z0-9+/]{60,}={0,2}\b",
        "Long Base64-looking blob (possible hidden payload)",
    ),
    _sig(
        "enc.decode_request", "encoding", Severity.MEDIUM, 0.50,
        r"\b(?:decode|base64-?decode|rot13|reverse|unscramble)\b.{0,30}?\b(?:and|then)\b.{0,20}?\b(?:follow|execute|run|do|obey)\b",
        "Asks the model to decode then execute",
    ),
]


SIGNATURES: List[Signature] = (
    _INSTRUCTION_OVERRIDE
    + _ROLE_INJECTION
    + _PROMPT_LEAK
    + _EXFILTRATION
    + _JAILBREAK
    + _TOOL_INJECTION
    + _BOUNDARY
    + _ENCODING
)
