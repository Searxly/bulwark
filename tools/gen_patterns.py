"""Generate the TypeScript and Swift signature databases from the Python one.

Bulwark kept three hand-maintained copies of the same 131 signatures. That is
exactly how they drifted: the conformance harness measured 529 verdict
divergences across the corpus, and most of them were simply a signature that
existed in one language and not another.

Three copies of one fact is not a style choice, it is a bug waiting to happen.
So there is now one source of truth — ``python/src/bulwark/patterns.py`` — and
the other two are generated from it.

    python3 tools/gen_patterns.py            # regenerate
    python3 tools/gen_patterns.py --check    # fail if they are stale (CI)

Regex dialects
--------------
The three engines are not the same engine, and the differences are exactly
where a mechanical translation would quietly change behaviour:

* Python's ``\\w`` and ``\\b`` are Unicode-aware. JavaScript's are ASCII-only.
  ICU's are Unicode-aware, so Swift needs no adjustment.
* JavaScript's ``u`` flag rejects escapes it considers redundant, so a few of
  them have to be normalized on the way out.

``\\w`` is rewritten for JavaScript into an explicit Unicode class. ``\\b`` is
left alone: rewriting it correctly needs to know whether each occurrence is a
leading or a trailing boundary, and getting that wrong silently breaks the
pattern. The English signatures — which are almost all of them — are ASCII and
unaffected. Where a boundary genuinely matters against non-ASCII text, the
signature gets an explicit entry in ``JS_OVERRIDES`` below, and the conformance
harness is what finds the ones that need it.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "python" / "src"))

from bulwark.patterns import SIGNATURES, Signature  # noqa: E402

TS_OUT = ROOT / "typescript" / "src" / "patterns.ts"
SWIFT_OUT = ROOT / "swift" / "Sources" / "Bulwark" / "Patterns.swift"

BANNER_TS = """/**
 * Signature database of known prompt-injection patterns. Each signature carries
 * a weight in [0, 1); the detector combines them with a noisy-OR.
 *
 * GENERATED FILE — DO NOT EDIT.
 * Source of truth: python/src/bulwark/patterns.py
 * Regenerate:      python3 tools/gen_patterns.py
 *
 * Three hand-maintained copies of one signature database is how they drift, so
 * there is one copy and two generated from it.
 */
"""

BANNER_SWIFT = """// Signature database of known prompt-injection patterns. Each carries a weight
// in [0, 1); the detector combines them with a noisy-OR.
//
// GENERATED FILE — DO NOT EDIT.
// Source of truth: python/src/bulwark/patterns.py
// Regenerate:      python3 tools/gen_patterns.py
//
// Three hand-maintained copies of one signature database is how they drift, so
// there is one copy and two generated from it.
"""

# JavaScript's \w is ASCII-only; Python's is not. Everything else about these
# patterns translates directly.
_JS_WORD = r"[\p{L}\p{N}_]"
_JS_NON_WORD = r"[^\p{L}\p{N}_]"

# Signatures whose JavaScript form needs more than the mechanical rewrite.
# Keyed by signature id; the value replaces the pattern outright. Add an entry
# when tools/conformance.py reports a divergence that the generic rules cannot
# fix, and say why.
JS_OVERRIDES: Dict[str, str] = {}

# Same, for Swift. ICU matches Python closely enough that this is usually empty.
SWIFT_OVERRIDES: Dict[str, str] = {}


# Under the `u` flag JavaScript accepts only a fixed set of escapes and rejects
# everything else as "Invalid escape" — including redundant ones Python tolerates
# happily, like `\"`. These are the ones that must keep their backslash.
_JS_KEEP_ESCAPED = set("^$\\.*+?()[]{}|/bBdDfnrsStvwW0xucpPkq")
_JS_KEEP_ESCAPED |= set("123456789")   # backreferences


def _js_needs_escape(ch: str, in_class: bool) -> bool:
    if ch in _JS_KEEP_ESCAPED:
        return True
    # `\-` is legal inside a character class and illegal outside one.
    return ch == "-" and in_class


def to_javascript(pattern: str) -> str:
    """Rewrite a Python pattern for JavaScript's ``u``-flag dialect."""
    out: List[str] = []
    i = 0
    n = len(pattern)
    in_class = False
    while i < n:
        ch = pattern[i]
        if ch == "\\" and i + 1 < n:
            nxt = pattern[i + 1]
            if nxt == "w":
                # Inside a character class the brackets of the replacement would
                # nest, so splice its contents in instead.
                out.append(_JS_WORD[1:-1] if in_class else _JS_WORD)
                i += 2
                continue
            if nxt == "W" and not in_class:
                out.append(_JS_NON_WORD)
                i += 2
                continue
            if _js_needs_escape(nxt, in_class):
                out.append(ch)
            # Otherwise drop the backslash: a redundant escape such as `\"` is
            # fine in Python and a syntax error in JavaScript under `u`.
            out.append(nxt)
            i += 2
            continue
        if ch == "[" and not in_class:
            in_class = True
        elif ch == "]" and in_class:
            in_class = False
        out.append(ch)
        i += 1
    return "".join(out)


def to_swift(pattern: str) -> str:
    """ICU is close enough to Python's dialect that this is the identity."""
    return pattern


def _ts_literal(pattern: str) -> str:
    """A TypeScript string literal for a regex source, backslashes intact."""
    escaped = pattern.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _swift_literal(pattern: str) -> str:
    """A Swift raw string literal, widening the delimiter if the pattern
    contains the closing sequence."""
    hashes = "#"
    while hashes + '"' in pattern or '"' + hashes in pattern:
        hashes += "#"
    return f'{hashes}"{pattern}"{hashes}'


def _severity_ts(sig: Signature) -> str:
    return f'"{sig.severity.value}"'


def _severity_swift(sig: Signature) -> str:
    return f".{sig.severity.value}"


def render_typescript(signatures: List[Signature]) -> str:
    lines = [BANNER_TS, "", 'import type { Severity } from "./types.js";', "",
             "export interface Signature {", "  id: string;", "  category: string;",
             "  severity: Severity;", "  weight: number;", "  regex: RegExp;",
             "  description: string;", "}", "",
             "function sig(", "  id: string,", "  category: string,",
             "  severity: Severity,", "  weight: number,", "  pattern: string,",
             "  description: string,", "): Signature {",
             "  // `u` gives \\p{...} its meaning; `i` and `m` mirror Python's",
             "  // re.IGNORECASE | re.MULTILINE.",
             '  return { id, category, severity, weight, regex: new RegExp(pattern, "imu"), description };',
             "}", "", "export const SIGNATURES: Signature[] = ["]

    for sig in signatures:
        pattern = JS_OVERRIDES.get(sig.id, to_javascript(sig.regex.pattern))
        lines.append("  sig(")
        lines.append(f'    "{sig.id}", "{sig.category}", {_severity_ts(sig)}, {sig.weight},')
        lines.append(f"    {_ts_literal(pattern)},")
        lines.append(f'    {_ts_literal(sig.description)[0:0]}"{sig.description}",')
        lines.append("  ),")
    lines.append("];")
    lines.append("")
    return "\n".join(lines)


def render_swift(signatures: List[Signature]) -> str:
    lines = [BANNER_SWIFT, "", "import Foundation", "", "struct Signature: Sendable {",
             "    let id: String", "    let category: String", "    let severity: Severity",
             "    let weight: Double", "    let regex: CompiledRegex", "    let description: String",
             "}", "", "private func sig(",
             "    _ id: String, _ category: String, _ severity: Severity, _ weight: Double,",
             "    _ pattern: String, _ description: String", ") -> Signature {",
             "    Signature(id: id, category: category, severity: severity, weight: weight,",
             "              regex: CompiledRegex(pattern), description: description)", "}", "",
             "let signatures: [Signature] = ["]

    for sig in signatures:
        pattern = SWIFT_OVERRIDES.get(sig.id, to_swift(sig.regex.pattern))
        description = sig.description.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'    sig("{sig.id}", "{sig.category}", {_severity_swift(sig)}, {sig.weight},')
        lines.append(f"        {_swift_literal(pattern)},")
        lines.append(f'        "{description}"),')
    lines.append("]")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if the generated files are stale")
    args = ap.parse_args()

    outputs = {TS_OUT: render_typescript(SIGNATURES), SWIFT_OUT: render_swift(SIGNATURES)}

    if args.check:
        stale = [p for p, text in outputs.items() if not p.exists() or p.read_text(encoding="utf-8") != text]
        if stale:
            print("Generated signature databases are stale:", file=sys.stderr)
            for p in stale:
                print(f"  {p.relative_to(ROOT)}", file=sys.stderr)
            print("\nRun: python3 tools/gen_patterns.py", file=sys.stderr)
            return 1
        print(f"generated signature databases are up to date ({len(SIGNATURES)} signatures)")
        return 0

    for path, text in outputs.items():
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}  ({len(SIGNATURES)} signatures)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
