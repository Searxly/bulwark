"""Check that the model's answer actually came from the source.

Every other output check asks "does this reply look dangerous?". This one asks a
sharper question: **is this reply derived from the document we gave it?**

The distinction matters because the strongest evidence that a summarizer was
steered is not a scary phrase — an attacker can phrase a payload innocuously —
it is a summary containing something that was never in the source. A domain, an
email address, a URL that the document does not mention cannot have come from
summarizing the document. It came from an instruction the model obeyed.

This is a cheap, deterministic approximation of provenance:

* **Reference grounding** (strong, language-independent) — every host, URL and
  email address in the output must occur in the source. A novel one is a
  ``critical``/``high`` finding, because an exfiltration channel that survived
  every other layer is exactly what it looks like.
* **Lexical grounding** (weak, language-dependent) — what fraction of the
  output's content words occur in the source. A faithful summary reuses the
  source's vocabulary; a hijacked reply talks about something else. Skipped
  when the summary was requested in a different language than the source, where
  the measure is meaningless.

Both are advisory signals feeding the same noisy-OR as everything else. Neither
can be trusted alone: a paraphrase-heavy summary scores low on lexical grounding
without being an attack, which is why that signal is weighted well below the
reference check.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Set

from .types import Finding, Severity, Stage

# Hosts that carry no exfiltration value on their own: an attacker cannot
# receive data at a domain they do not control, and these are the ones a model
# is most likely to mention from its own knowledge rather than from the source.
_UBIQUITOUS_HOSTS = frozenset({
    "example.com", "example.org", "example.net", "localhost",
    "w3.org", "schema.org", "iana.org", "ietf.org",
})

_URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>\"'\)\]\}]+", re.IGNORECASE)
_BARE_HOST_RE = re.compile(
    # The lookbehind excludes '-' as well as word characters so that
    # "mailbox-relay.io" yields one host, not a phantom "relay.io" too.
    r"\b(?<![@.\w-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|org|net|io|dev|app|co|ai|me|xyz|info|biz|ru|cn|uk|de|fr|jp|top|site|online|link|click))"
    r"(?![\w.-])",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_WORD_RE = re.compile(r"[^\W\d_]{4,}", re.UNICODE)

# Small, deliberately English-centric list. Its only job is to stop function
# words from inflating the grounding ratio; unknown-language text simply keeps
# more words, which makes the measure more conservative, not less.
_STOPWORDS = frozenset("""
about above after again against because been before being below between both
during each further have here into itself more most only other over same some
such than that their them then there these they this those through under until
very were what when where which while with your
""".split())


@dataclass
class GroundingReport:
    """How much of the output can be traced back to the source."""

    ratio: float                                  # 0..1 lexical overlap, 1.0 when skipped
    lexical_checked: bool
    novel_hosts: List[str] = field(default_factory=list)
    novel_emails: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    @property
    def grounded(self) -> bool:
        return not self.novel_hosts and not self.novel_emails and not self.findings


def _fold(text: str) -> str:
    return unicodedata.normalize("NFKC", text).lower()


def _normalize_host(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def extract_hosts(text: str) -> Set[str]:
    """Every host referenced by a URL or a bare domain in ``text``."""
    hosts: Set[str] = set()
    for match in _URL_RE.finditer(text):
        raw = match.group(0)
        raw = re.sub(r"^https?://", "", raw, flags=re.IGNORECASE)
        # Drop userinfo before the host — https://good.com@evil.example is evil.
        raw = raw.split("@")[-1]
        host = re.split(r"[/?#:]", raw, 1)[0]
        if host:
            hosts.add(_normalize_host(host))
    for match in _BARE_HOST_RE.finditer(text):
        hosts.add(_normalize_host(match.group(1)))
    return {h for h in hosts if h and h not in _UBIQUITOUS_HOSTS}


def extract_emails(text: str) -> Set[str]:
    return {m.group(0).lower() for m in _EMAIL_RE.finditer(text)}


def content_words(text: str) -> List[str]:
    return [w for w in _WORD_RE.findall(_fold(text)) if w not in _STOPWORDS]


def check_grounding(
    output: str,
    source: str,
    *,
    check_lexical: bool = True,
    min_words_for_lexical: int = 25,
    lexical_floor: float = 0.30,
) -> GroundingReport:
    """Compare a model reply against the source it was supposed to summarize.

    ``check_lexical`` should be False when the summary was requested in a
    different language than the source, or when the caller's task is not
    summarization — the vocabulary measure means nothing there. The reference
    checks always run; they do not depend on language.
    """
    findings: List[Finding] = []
    if not output or not output.strip():
        return GroundingReport(ratio=1.0, lexical_checked=False)

    source_folded = _fold(source)

    # --- reference grounding (strong) -------------------------------------
    source_hosts = extract_hosts(source)
    novel_hosts = sorted(
        h for h in extract_hosts(output)
        # A host is grounded if the source names it, or names it as a suffix
        # (the source may show "docs.example.com" and the summary "example.com").
        if h not in source_hosts
        and not any(h == s or s.endswith("." + h) or h.endswith("." + s) for s in source_hosts)
        and h not in source_folded
    )
    if novel_hosts:
        findings.append(Finding(
            Stage.VALIDATE, "ungrounded_host", Severity.CRITICAL,
            f"Output references {len(novel_hosts)} host(s) absent from the source: "
            + ", ".join(novel_hosts[:4]),
            weight=0.92,
            excerpt=novel_hosts[0][:80],
        ))

    source_emails = extract_emails(source)
    novel_emails = sorted(e for e in extract_emails(output) if e not in source_emails)
    if novel_emails:
        findings.append(Finding(
            Stage.VALIDATE, "ungrounded_email", Severity.HIGH,
            f"Output contains {len(novel_emails)} email address(es) absent from the source",
            weight=0.80,
            excerpt=novel_emails[0][:80],
        ))

    # --- lexical grounding (weak) -----------------------------------------
    ratio = 1.0
    checked = False
    if check_lexical:
        out_words = content_words(output)
        if len(out_words) >= min_words_for_lexical:
            checked = True
            source_words = set(content_words(source))
            if source_words:
                hits = sum(1 for w in out_words if w in source_words)
                ratio = hits / len(out_words)
                if ratio < lexical_floor:
                    findings.append(Finding(
                        Stage.VALIDATE, "low_grounding", Severity.MEDIUM,
                        f"Only {ratio:.0%} of the summary's content words appear in the source "
                        f"— the reply may not be derived from it",
                        weight=0.45,
                    ))

    return GroundingReport(
        ratio=round(ratio, 4),
        lexical_checked=checked,
        novel_hosts=novel_hosts,
        novel_emails=novel_emails,
        findings=findings,
    )
