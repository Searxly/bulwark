#!/usr/bin/env python3
"""Measure Bulwark's detection on a labeled corpus.

Runs ``bulwark.scan`` over ``dataset.jsonl`` (one ``{"text", "label", "group"}``
record per line, label ∈ {attack, benign}) and reports recall, precision, F1,
and a per-group breakdown. No dependencies beyond the package itself.

    python eval/run_eval.py                 # human-readable report
    python eval/run_eval.py --json          # machine-readable
    python eval/run_eval.py --threshold 0.4 # sweep the decision threshold

Exit code is non-zero if recall or precision falls below --min-recall /
--min-precision, so it can double as a regression gate in CI.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python", "src"))

from bulwark import scan  # noqa: E402

DATASET = os.path.join(os.path.dirname(__file__), "dataset.jsonl")


def load(path: str):
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                rows.append(json.loads(line))
    return rows


def evaluate(rows, threshold: float):
    tp = fp = tn = fn = 0
    by_group = defaultdict(lambda: {"total": 0, "hit": 0})
    misses = []
    for row in rows:
        is_attack = row["label"] == "attack"
        flagged = scan(row["text"], threshold=threshold).injected
        g = by_group[row.get("group", "—")]
        g["total"] += 1
        if is_attack:
            if flagged:
                tp += 1
                g["hit"] += 1
            else:
                fn += 1
                misses.append(("missed attack", row))
        else:
            if flagged:
                fp += 1
                misses.append(("false positive", row))
            else:
                tn += 1
                g["hit"] += 1

    recall = tp / (tp + fn) if (tp + fn) else 1.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "counts": {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "n": len(rows)},
        "recall": recall,
        "precision": precision,
        "f1": f1,
        "by_group": {k: v for k, v in sorted(by_group.items())},
        "misses": misses,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Evaluate Bulwark detection on a labeled corpus.")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--min-recall", type=float, default=0.90, help="Fail if recall drops below this.")
    ap.add_argument("--min-precision", type=float, default=0.98, help="Fail if precision drops below this.")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--dataset", default=DATASET)
    args = ap.parse_args(argv)

    rows = load(args.dataset)
    res = evaluate(rows, args.threshold)

    if args.json:
        printable = {k: v for k, v in res.items() if k != "misses"}
        printable["misses"] = [{"kind": k, **r} for k, r in res["misses"]]
        print(json.dumps(printable, indent=2))
    else:
        c = res["counts"]
        print(f"Bulwark eval — {c['n']} samples @ threshold {args.threshold}")
        print(f"  recall    {res['recall']:.3f}   ({c['tp']}/{c['tp'] + c['fn']} attacks caught)")
        print(f"  precision {res['precision']:.3f}   ({c['fp']} false positive(s) on {c['tn'] + c['fp']} benign)")
        print(f"  F1        {res['f1']:.3f}")
        print("\n  by group:")
        for name, g in res["by_group"].items():
            print(f"    {name:22} {g['hit']}/{g['total']}")
        if res["misses"]:
            print("\n  misclassified:")
            for kind, row in res["misses"]:
                print(f"    [{kind}] {row['text'][:70]!r}")

    ok = res["recall"] >= args.min_recall and res["precision"] >= args.min_precision
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
