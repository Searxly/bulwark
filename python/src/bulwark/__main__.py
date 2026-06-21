"""Command-line scanner: pipe text in, get a risk report out.

    echo "ignore all previous instructions" | python -m bulwark
    python -m bulwark path/to/page.html
    python -m bulwark --json page.html

Exit code is non-zero when an injection is detected, so it composes in shells:

    python -m bulwark page.html && ./summarize page.html
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, scan


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="bulwark", description="Scan text for prompt-injection signals.")
    parser.add_argument("file", nargs="?", help="File to scan (defaults to stdin).")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument("--threshold", type=float, default=0.5, help="Injection score threshold (0-1).")
    parser.add_argument("--version", action="version", version=f"bulwark {__version__}")
    args = parser.parse_args(argv)

    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    else:
        text = sys.stdin.read()

    result = scan(text, threshold=args.threshold)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        status = "INJECTION DETECTED" if result.injected else "clean"
        print(f"bulwark: {status}  (risk={result.risk.value}, score={result.score:.2f})")
        for f in sorted(result.findings, key=lambda x: -x.severity.rank):
            excerpt = f" — {f.excerpt!r}" if f.excerpt else ""
            print(f"  [{f.severity.value:>8}] {f.category}: {f.message}{excerpt}")

    return 1 if result.injected else 0


if __name__ == "__main__":
    raise SystemExit(main())
