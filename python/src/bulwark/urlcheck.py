"""Decide whether a URL is a destination or a delivery mechanism.

Wherever an LLM system touches a URL — a link a summarizer emitted, an argument
an agent wants to pass to ``navigate`` — the same two questions apply. *Where
does this actually point?* and *how much data is riding along?*

Both are harder than they look, because a host is not a string. All of these
name 127.0.0.1, and a substring check for "127.0.0.1" catches none of them:

    http://2130706433/     http://0177.0.0.1/    http://0x7f.0.0.1/
    http://127.1/          http://[::ffff:127.0.0.1]/

And all of these look like they point at a domain you trust, but do not:

    https://trusted.example.com@attacker.test/
    https://trusted.example.com.attacker.test/
    https://xn--trustd-9wa.example/            (homograph)

So the host is *canonicalized* the way the network stack would canonicalize it —
the full ``inet_aton`` grammar, IPv6 forms, IPv4-mapped addresses — and only
then classified. The data-carrying checks are separate: an opaque blob is
exfiltration-shaped wherever it sits, and attackers move it from the query
string to the path, the fragment, or a subdomain precisely because guards tend
to only look at the query.

**This is syntactic analysis only.** No DNS is resolved — Bulwark stays
deterministic and dependency-free — so a public hostname that resolves to
169.254.169.254 passes here. Keep a resolver-level SSRF guard in the fetch layer
too; this is the check you can run before you have a socket, not a replacement
for the one you run when you do.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Sequence, Set, Tuple

from .types import Finding, Severity, Stage


class HostKind(str, Enum):
    DOMAIN = "domain"
    IPV4 = "ipv4"          # includes decimal/octal/hex/short forms once canonicalized
    IPV6 = "ipv6"
    EMPTY = "empty"
    MALFORMED = "malformed"


# Cloud instance-metadata endpoints. Reaching one from a hijacked agent hands an
# attacker the machine's credentials, which makes them the highest-value target
# in the private ranges rather than just another internal address.
_METADATA_HOSTS = frozenset({
    "169.254.169.254",          # AWS / Azure / GCP / DigitalOcean IMDS
    "169.254.170.2",            # AWS ECS task metadata
    "100.100.100.200",          # Alibaba Cloud
    "192.0.0.192",              # Oracle Cloud
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
})
_METADATA_IPV6 = ("fd00:ec2::254",)

_LOCAL_SUFFIXES = (".local", ".internal", ".localhost", ".home.arpa", ".localdomain")
_LOCAL_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"})

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):")
_OPAQUE_RUN_RE = re.compile(r"[A-Za-z0-9+/=_-]{8,}")
_LABEL_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

# Schemes that do something other than fetch a document, and are therefore never
# a legitimate "go here" target from untrusted content.
_ACTIVE_SCHEMES = frozenset({"javascript", "data", "vbscript", "file", "jar", "blob", "about"})


@dataclass
class URLAssessment:
    """Everything syntactic analysis can tell you about one URL."""

    raw: str
    scheme: str = ""
    userinfo: Optional[str] = None
    host: str = ""
    canonical_host: str = ""
    port: Optional[int] = None
    path: str = ""
    query: str = ""
    fragment: str = ""

    kind: HostKind = HostKind.EMPTY
    is_private: bool = False
    is_metadata: bool = False
    is_punycode: bool = False
    is_mixed_script: bool = False
    has_credentials: bool = False

    opaque_in_query: int = 0
    opaque_in_path: int = 0
    opaque_in_fragment: int = 0
    opaque_in_subdomain: int = 0

    findings: List[Finding] = field(default_factory=list)

    @property
    def max_opaque(self) -> int:
        return max(self.opaque_in_query, self.opaque_in_path,
                   self.opaque_in_fragment, self.opaque_in_subdomain)

    @property
    def safe(self) -> bool:
        return not self.findings


# --- host canonicalization -------------------------------------------------

def _parse_ipv4_part(part: str) -> Optional[int]:
    """One component of an inet_aton-style address: 0x-hex, 0-octal, decimal."""
    if not part:
        return None
    try:
        if part.lower().startswith("0x"):
            return int(part[2:], 16) if len(part) > 2 else None
        if part.startswith("0") and len(part) > 1:
            return int(part, 8)
        return int(part, 10)
    except ValueError:
        return None


def parse_ipv4(host: str) -> Optional[int]:
    """Canonicalize any inet_aton-accepted IPv4 spelling to a 32-bit integer.

    Handles the four forms the C library accepts and browsers still honour:
    ``a.b.c.d``, ``a.b.c`` (c is 16-bit), ``a.b`` (b is 24-bit) and a bare
    32-bit ``a`` — each component independently decimal, octal or hex. Returns
    None when the host is not an IPv4 literal in any of those spellings.
    """
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    values: List[int] = []
    for part in parts:
        value = _parse_ipv4_part(part)
        if value is None or value < 0:
            return None
        values.append(value)

    # Every component but the last is one byte; the last absorbs the remainder.
    limit = 1 << (8 * (5 - len(values)))
    if values[-1] >= limit:
        return None
    if any(v > 0xFF for v in values[:-1]):
        return None

    result = values[-1]
    for i, value in enumerate(values[:-1]):
        result |= value << (8 * (3 - i))
    return result if result <= 0xFFFFFFFF else None


def ipv4_to_string(value: int) -> str:
    return ".".join(str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0))


_PRIVATE_V4_RANGES: Tuple[Tuple[int, int], ...] = tuple(
    (base, base + (1 << (32 - bits)) - 1)
    for base, bits in (
        (0x00000000, 8),    # 0.0.0.0/8      this network
        (0x0A000000, 8),    # 10/8           private
        (0x7F000000, 8),    # 127/8          loopback
        (0xA9FE0000, 16),   # 169.254/16     link-local (incl. cloud metadata)
        (0xAC100000, 12),   # 172.16/12      private
        (0xC0A80000, 16),   # 192.168/16     private
        (0x64400000, 10),   # 100.64/10      CGNAT
        (0xC0000000, 24),   # 192.0.0/24     IETF protocol assignments
        (0xC0000200, 24),   # 192.0.2/24     TEST-NET-1
        (0xC6120000, 15),   # 198.18/15      benchmarking
        (0xC6336400, 24),   # 198.51.100/24  TEST-NET-2
        (0xCB007100, 24),   # 203.0.113/24   TEST-NET-3
        (0xE0000000, 4),    # 224/4          multicast
        (0xF0000000, 4),    # 240/4          reserved + broadcast
    )
)


def _ipv4_is_private(value: int) -> bool:
    return any(low <= value <= high for low, high in _PRIVATE_V4_RANGES)


def _ipv6_is_private(host: str) -> bool:
    h = host.strip("[]").lower().split("%")[0]   # drop any zone id
    if h in ("::1", "::", "0:0:0:0:0:0:0:1"):
        return True
    if h.startswith("fe80:") or h.startswith("fe8") or h.startswith("fe9") \
            or h.startswith("fea") or h.startswith("feb"):
        return True                              # fe80::/10 link-local
    if h.startswith("fc") or h.startswith("fd"):
        return True                              # fc00::/7 unique-local
    if h.startswith("::ffff:") or h.startswith("::"):
        # IPv4-mapped and IPv4-compatible forms carry a v4 address inside.
        tail = h.rsplit(":", 1)[-1]
        value = parse_ipv4(tail) if "." in tail else None
        if value is not None:
            return _ipv4_is_private(value)
    return False


def _scripts_of(text: str) -> Set[str]:
    """Coarse script names for the letters in ``text`` — enough to notice a
    label mixing Latin with Cyrillic, which is what a homograph does."""
    scripts: Set[str] = set()
    for ch in text:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        scripts.add(name.split()[0])
    return scripts


# --- parsing ---------------------------------------------------------------

def split_url(raw: str) -> Tuple[str, Optional[str], str, Optional[int], str, str, str]:
    """Split a URL without the leniency ``urllib.parse`` applies.

    Returns ``(scheme, userinfo, host, port, path, query, fragment)``. A value
    with no scheme is treated as a bare host, matching how a model or a user
    would read ``evil.example/path``.
    """
    text = raw.strip()
    # Control and whitespace characters inside a URL are how parsers get split
    # against each other; strip them but remember the string was odd.
    text = "".join(ch for ch in text if ch.isprintable() and not ch.isspace())

    scheme = ""
    match = _SCHEME_RE.match(text)
    if match:
        scheme = match.group(1).lower()
        text = text[match.end():]
        if text.startswith("//"):
            text = text[2:]
    elif text.startswith("//"):
        text = text[2:]     # scheme-relative

    fragment = ""
    if "#" in text:
        text, fragment = text.split("#", 1)
    query = ""
    if "?" in text:
        text, query = text.split("?", 1)
    path = ""
    if "/" in text:
        slash = text.index("/")
        text, path = text[:slash], text[slash:]

    userinfo = None
    if "@" in text:
        # Last '@' wins: https://a@b@evil.test authenticates to evil.test.
        userinfo, text = text.rsplit("@", 1)

    port: Optional[int] = None
    host = text
    if host.startswith("["):                     # IPv6 literal
        close = host.find("]")
        if close != -1:
            rest = host[close + 1:]
            host = host[:close + 1]
            if rest.startswith(":") and rest[1:].isdigit():
                port = int(rest[1:])
    elif ":" in host:
        head, _, tail = host.rpartition(":")
        if tail.isdigit():
            host, port = head, int(tail)

    return scheme, userinfo, host.rstrip("."), port, path, query, fragment


def classify_host(host: str) -> Tuple[HostKind, str]:
    """Return the host's kind and its canonical spelling."""
    if not host:
        return HostKind.EMPTY, ""
    # A fully-qualified name may carry a trailing root dot. Resolvers treat
    # "localhost." and "localhost" as the same name, so anything comparing
    # hostnames must too — otherwise one dot walks straight past a host check.
    lowered = host.lower().rstrip(".")
    if not lowered:
        return HostKind.EMPTY, ""
    if lowered.startswith("[") and lowered.endswith("]"):
        return HostKind.IPV6, lowered
    if ":" in lowered:
        return HostKind.IPV6, lowered
    value = parse_ipv4(lowered)
    if value is not None:
        return HostKind.IPV4, ipv4_to_string(value)
    labels = lowered.split(".")
    if all(_LABEL_RE.match(label) or any(ord(c) > 127 for c in label) for label in labels if label):
        return HostKind.DOMAIN, lowered
    return HostKind.MALFORMED, lowered


def is_private_host(host: str) -> bool:
    """Syntactic private/local check across every IPv4 and IPv6 spelling."""
    kind, canonical = classify_host(host)
    if kind == HostKind.IPV4:
        return _ipv4_is_private(parse_ipv4(host.lower()) or 0)
    if kind == HostKind.IPV6:
        return _ipv6_is_private(canonical)
    if kind in (HostKind.EMPTY, HostKind.MALFORMED):
        return False
    if canonical in _LOCAL_NAMES or canonical.endswith(_LOCAL_SUFFIXES):
        return True
    # A single-label host resolves through the local search domain.
    return "." not in canonical


def is_metadata_host(host: str) -> bool:
    kind, canonical = classify_host(host)
    if canonical in _METADATA_HOSTS:
        return True
    if kind == HostKind.IPV6 and canonical.strip("[]") in _METADATA_IPV6:
        return True
    return False


def _longest_opaque(text: str) -> int:
    longest = 0
    for match in _OPAQUE_RUN_RE.finditer(text):
        longest = max(longest, len(match.group(0)))
    return longest


# --- the check -------------------------------------------------------------

def analyze(
    raw: str,
    *,
    allowed_schemes: Sequence[str] = ("http", "https"),
    max_length: int = 2_048,
    max_opaque: int = 48,
    max_opaque_subdomain: int = 24,
    allow_private: bool = False,
) -> URLAssessment:
    """Assess one URL.

    ``max_opaque`` is the longest opaque run tolerated in a query, path or
    fragment before it reads as smuggled data. Subdomains get the tighter
    ``max_opaque_subdomain``: DNS labels are chosen by humans and are short, so
    a 30-character random label is already anomalous where the same run in a
    query string might be a legitimate session token.
    """
    scheme, userinfo, host, port, path, query, fragment = split_url(raw)
    kind, canonical = classify_host(host)

    assessment = URLAssessment(
        raw=raw, scheme=scheme, userinfo=userinfo, host=host, canonical_host=canonical,
        port=port, path=path, query=query, fragment=fragment, kind=kind,
    )

    def add(category: str, severity: Severity, message: str, weight: float) -> None:
        assessment.findings.append(Finding(
            Stage.VALIDATE, category, severity, message, weight=weight,
            excerpt=raw[:100],
        ))

    # Scheme. An active scheme is not a destination at all; it is code.
    active_scheme = bool(scheme) and scheme in _ACTIVE_SCHEMES
    if active_scheme:
        add("url_active_scheme", Severity.CRITICAL,
            f"URL uses the '{scheme}:' scheme, which executes rather than fetches", 0.95)
    elif scheme and allowed_schemes and scheme not in allowed_schemes:
        add("url_scheme", Severity.HIGH,
            f"URL scheme '{scheme}' is not in the allowed set", 0.80)

    if userinfo:
        assessment.has_credentials = True
        add("url_credentials", Severity.HIGH,
            f"URL embeds userinfo before the host — the real destination is '{canonical}', "
            f"not '{userinfo.split(':')[0]}'", 0.82)

    # An active-scheme URL has no host in any meaningful sense, so reporting the
    # leftovers as a malformed hostname would just be noise beside the real
    # (critical) finding.
    if kind == HostKind.MALFORMED and not active_scheme:
        add("url_malformed", Severity.MEDIUM, f"URL host '{host}' is not a valid hostname", 0.50)

    assessment.is_metadata = is_metadata_host(host)
    assessment.is_private = is_private_host(host)
    if assessment.is_metadata:
        add("url_metadata_endpoint", Severity.CRITICAL,
            f"URL targets a cloud instance-metadata endpoint ({canonical})", 0.96)
    elif assessment.is_private and not allow_private:
        add("url_private_host", Severity.HIGH,
            f"URL targets a private or local host ({canonical or host})", 0.80)

    # The canonical form differing from what was written is itself the tell: an
    # honest link to 10.0.0.1 says "10.0.0.1", not "167772161".
    if kind == HostKind.IPV4 and canonical != host.lower():
        add("url_obfuscated_ip", Severity.HIGH,
            f"URL host '{host}' is an obfuscated spelling of {canonical}", 0.82)

    labels = canonical.split(".") if kind == HostKind.DOMAIN else []
    if any(label.startswith("xn--") for label in labels):
        assessment.is_punycode = True
        add("url_punycode", Severity.MEDIUM,
            f"URL host '{canonical}' uses punycode — it may not read as it renders", 0.55)
    for label in labels:
        scripts = _scripts_of(label)
        if len(scripts) > 1:
            assessment.is_mixed_script = True
            add("url_mixed_script", Severity.HIGH,
                f"URL host label '{label}' mixes {', '.join(sorted(scripts))} scripts — homograph", 0.78)
            break

    if max_length and len(raw) > max_length:
        add("url_length", Severity.HIGH,
            f"URL is {len(raw)} characters — long enough to be carrying a payload", 0.78)

    assessment.opaque_in_query = _longest_opaque(query)
    assessment.opaque_in_path = _longest_opaque(path)
    assessment.opaque_in_fragment = _longest_opaque(fragment)
    assessment.opaque_in_subdomain = max(
        (_longest_opaque(label) for label in labels[:-2]), default=0
    )
    for where, length, limit in (
        ("query string", assessment.opaque_in_query, max_opaque),
        ("path", assessment.opaque_in_path, max_opaque),
        ("fragment", assessment.opaque_in_fragment, max_opaque),
        ("subdomain", assessment.opaque_in_subdomain, max_opaque_subdomain),
    ):
        if limit and length > limit:
            add("url_opaque_payload", Severity.HIGH,
                f"URL {where} carries a {length}-character opaque run — possible encoded exfiltration",
                0.80)
            break

    return assessment
