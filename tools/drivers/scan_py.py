"""Conformance driver — Python.

Reads the merged corpus JSONL on stdin (or from a path argument), writes one
result object per line to stdout. The TypeScript and Swift drivers emit the
identical shape, so ``tools/conformance.py`` can diff three implementations
byte-for-byte.

    python3 tools/drivers/scan_py.py corpus/corpus.jsonl > /tmp/py.jsonl
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python" / "src"))

from bulwark import fold_detection, sanitize_text, scan  # noqa: E402
from bulwark.detect import scan as detect_scan  # noqa: E402


def result_for(text: str, threshold: float) -> dict:
    san = sanitize_text(text)
    det = detect_scan(
        san.text,
        threshold=threshold,
        extra_findings=san.findings,
        also_scan=fold_detection(san.text),
    )
    return {
        "injected": det.injected,
        # 4dp is the contract: enough to catch real divergence, loose enough to
        # survive the last-bit float differences between three languages.
        "score": round(det.score, 4),
        "risk": det.risk.value,
        "patterns": sorted({f.pattern_id for f in det.findings if f.pattern_id}),
        "categories": sorted({f.category for f in det.findings}),
        "sanitized_len": len(san.text),
    }


def main() -> int:
    threshold = 0.5
    src = sys.stdin
    if len(sys.argv) > 1:
        src = open(sys.argv[1], encoding="utf-8")
    for line in src:
        line = line.strip()
        if not line:
            continue
        case = json.loads(line)
        out = {"id": case["id"], **result_for(case["text"], threshold)}
        sys.stdout.write(json.dumps(out, ensure_ascii=False, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
