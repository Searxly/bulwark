"""Grade Bulwark's detector against the ground-truth corpus, with a CI gate.

    python3 tools/bench.py                     # human-readable report
    python3 tools/bench.py --json              # machine-readable
    python3 tools/bench.py --write-baseline    # record the current numbers
    python3 tools/bench.py --gate              # fail if we regressed vs the baseline

A security library that ships regexes without measurements is asking to be
trusted on vibes. This turns "we catch a lot" into a number that CI defends:
recall may not fall and the false-positive rate may not rise.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "python" / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import corpus as corpus_mod  # noqa: E402
from corpus import Case  # noqa: E402

from bulwark import scan  # noqa: E402

BASELINE_PATH = corpus_mod.CORPUS_DIR / "BASELINE.json"

# How far a metric may drift before the gate fails. Recall and FPR are gated
# hard (a regression is a regression); the tolerance only absorbs corpus growth.
TOLERANCE = 0.005


class Outcome:
    """One graded case."""

    __slots__ = ("case", "predicted", "score", "risk", "patterns", "elapsed_ms")

    def __init__(self, case: Case, predicted: bool, score: float, risk: str,
                 patterns: List[str], elapsed_ms: float):
        self.case = case
        self.predicted = predicted
        self.score = score
        self.risk = risk
        self.patterns = patterns
        self.elapsed_ms = elapsed_ms

    @property
    def correct(self) -> bool:
        return self.predicted == self.case.expect_injected


def run(cases: List[Case], threshold: float = 0.5) -> List[Outcome]:
    out: List[Outcome] = []
    for case in cases:
        start = time.perf_counter()
        result = scan(case.text, threshold=threshold)
        elapsed = (time.perf_counter() - start) * 1000
        out.append(Outcome(
            case=case,
            predicted=result.injected,
            score=result.score,
            risk=result.risk.value,
            patterns=sorted({f.pattern_id for f in result.findings if f.pattern_id}),
            elapsed_ms=elapsed,
        ))
    return out


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def metrics(outcomes: List[Outcome], *, include_hard: bool = True) -> Dict[str, object]:
    sel = [o for o in outcomes if include_hard or not o.case.hard]
    tp = sum(1 for o in sel if o.case.is_attack and o.predicted)
    fn = sum(1 for o in sel if o.case.is_attack and not o.predicted)
    fp = sum(1 for o in sel if not o.case.is_attack and o.predicted)
    tn = sum(1 for o in sel if not o.case.is_attack and not o.predicted)

    precision = _rate(tp, tp + fp)
    recall = _rate(tp, tp + fn)
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "cases": len(sel),
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(_rate(fp, fp + tn), 4),
        "accuracy": round(_rate(tp + tn, len(sel)), 4),
    }


def by_group(outcomes: List[Outcome]) -> Dict[str, Dict[str, object]]:
    groups: Dict[str, List[Outcome]] = defaultdict(list)
    for o in outcomes:
        groups[f"{o.case.label}/{o.case.group}"].append(o)
    report = {}
    for name, items in sorted(groups.items()):
        hits = sum(1 for o in items if o.correct)
        report[name] = {
            "n": len(items),
            "correct": hits,
            "rate": round(_rate(hits, len(items)), 4),
        }
    return report


def by_language(outcomes: List[Outcome]) -> Dict[str, Dict[str, object]]:
    langs: Dict[str, List[Outcome]] = defaultdict(list)
    for o in outcomes:
        langs[o.case.language].append(o)
    return {
        lang: {
            "n": len(items),
            "correct": sum(1 for o in items if o.correct),
            "rate": round(_rate(sum(1 for o in items if o.correct), len(items)), 4),
        }
        for lang, items in sorted(langs.items())
    }


def build_report(outcomes: List[Outcome]) -> Dict[str, object]:
    times = sorted(o.elapsed_ms for o in outcomes)
    return {
        "overall": metrics(outcomes),
        "excluding_hard": metrics(outcomes, include_hard=False),
        "by_group": by_group(outcomes),
        "by_language": by_language(outcomes),
        "timing_ms": {
            "median": round(times[len(times) // 2], 3) if times else 0.0,
            "p95": round(times[int(len(times) * 0.95)], 3) if times else 0.0,
            "max": round(times[-1], 3) if times else 0.0,
        },
        "misses": [
            {"id": o.case.id, "group": o.case.group, "language": o.case.language,
             "score": round(o.score, 3), "hard": o.case.hard,
             "excerpt": " ".join(o.case.text.split())[:110]}
            for o in outcomes if o.case.is_attack and not o.predicted
        ],
        "false_positives": [
            {"id": o.case.id, "group": o.case.group, "language": o.case.language,
             "score": round(o.score, 3), "hard": o.case.hard,
             "patterns": o.patterns,
             "excerpt": " ".join(o.case.text.split())[:110]}
            for o in outcomes if not o.case.is_attack and o.predicted
        ],
    }


def format_report(report: Dict[str, object]) -> str:
    lines: List[str] = []
    o = report["overall"]           # type: ignore[index]
    h = report["excluding_hard"]    # type: ignore[index]
    t = report["timing_ms"]         # type: ignore[index]

    lines.append("Bulwark detection benchmark")
    lines.append("=" * 60)
    lines.append(
        f"  cases {o['cases']}   recall {o['recall']:.3f}   precision {o['precision']:.3f}"
        f"   F1 {o['f1']:.3f}   FPR {o['fpr']:.3f}"
    )
    lines.append(
        f"  excluding 'hard' cases:  recall {h['recall']:.3f}   FPR {h['fpr']:.3f}"
    )
    lines.append(
        f"  confusion: tp={o['tp']} fn={o['fn']} fp={o['fp']} tn={o['tn']}"
    )
    lines.append(
        f"  scan time: median {t['median']:.2f}ms  p95 {t['p95']:.2f}ms  max {t['max']:.2f}ms"
    )

    lines.append("")
    lines.append("  Per group")
    for name, g in report["by_group"].items():   # type: ignore[union-attr]
        bar = "#" * int(g["rate"] * 20)
        lines.append(f"    {name:<42} {g['correct']:>3}/{g['n']:<3} {g['rate']:.2f} {bar}")

    weakest = sorted(
        report["by_language"].items(),          # type: ignore[union-attr]
        key=lambda kv: kv[1]["rate"],
    )[:8]
    if weakest:
        lines.append("")
        lines.append("  Weakest languages")
        for lang, g in weakest:
            lines.append(f"    {lang:<10} {g['correct']:>3}/{g['n']:<3} {g['rate']:.2f}")

    misses = report["misses"]                    # type: ignore[assignment]
    if misses:
        lines.append("")
        lines.append(f"  Missed attacks ({len(misses)}) — the backlog")
        for m in misses[:25]:                    # type: ignore[index]
            flag = " [hard]" if m["hard"] else ""
            lines.append(f"    {m['id']:<10} {m['group']:<22} {m['score']:.2f}{flag}  {m['excerpt']}")
        if len(misses) > 25:                     # type: ignore[arg-type]
            lines.append(f"    … and {len(misses) - 25} more")

    fps = report["false_positives"]              # type: ignore[assignment]
    if fps:
        lines.append("")
        lines.append(f"  False positives ({len(fps)}) — benign content wrongly flagged")
        for m in fps[:25]:                       # type: ignore[index]
            flag = " [hard]" if m["hard"] else ""
            pats = ",".join(m["patterns"][:3])
            lines.append(f"    {m['id']:<10} {m['group']:<22} {m['score']:.2f}{flag}  [{pats}]  {m['excerpt']}")
        if len(fps) > 25:                        # type: ignore[arg-type]
            lines.append(f"    … and {len(fps) - 25} more")

    return "\n".join(lines)


def gate(report: Dict[str, object], baseline: Dict[str, object]) -> List[str]:
    """Return a list of regression messages — empty means the gate passes."""
    failures: List[str] = []
    cur = report["overall"]                      # type: ignore[index]
    old = baseline["overall"]                    # type: ignore[index]

    if cur["recall"] < old["recall"] - TOLERANCE:
        failures.append(
            f"recall regressed: {old['recall']:.4f} → {cur['recall']:.4f}"
        )
    if cur["fpr"] > old["fpr"] + TOLERANCE:
        failures.append(
            f"false-positive rate regressed: {old['fpr']:.4f} → {cur['fpr']:.4f}"
        )
    if cur["precision"] < old["precision"] - TOLERANCE:
        failures.append(
            f"precision regressed: {old['precision']:.4f} → {cur['precision']:.4f}"
        )

    # A case that used to be caught and now is not is a regression even if the
    # aggregate held up, because corpus growth can mask it.
    old_missed = {m["id"] for m in baseline.get("misses", [])}     # type: ignore[union-attr]
    new_missed = {m["id"] for m in report["misses"]}               # type: ignore[union-attr]
    regressed = sorted(new_missed - old_missed)
    if regressed:
        failures.append(f"attacks that used to be caught are now missed: {', '.join(regressed[:12])}")

    old_fp = {m["id"] for m in baseline.get("false_positives", [])}  # type: ignore[union-attr]
    new_fp = {m["id"] for m in report["false_positives"]}            # type: ignore[union-attr]
    new_fps = sorted(new_fp - old_fp)
    if new_fps:
        failures.append(f"new false positives: {', '.join(new_fps[:12])}")

    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="emit the report as JSON")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--write-baseline", action="store_true", help="record the current numbers as the baseline")
    ap.add_argument("--gate", action="store_true", help="exit non-zero if we regressed vs the baseline")
    args = ap.parse_args()

    cases = corpus_mod.load()
    outcomes = run(cases, threshold=args.threshold)
    report = build_report(outcomes)

    if args.write_baseline:
        BASELINE_PATH.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"baseline written → {BASELINE_PATH}")
        print(format_report(report))
        return 0

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(corpus_mod.summary(cases))
        print()
        print(format_report(report))

    if args.gate:
        if not BASELINE_PATH.exists():
            print("\nno baseline recorded — run with --write-baseline first", file=sys.stderr)
            return 2
        baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        failures = gate(report, baseline)
        if failures:
            print("\nGATE FAILED", file=sys.stderr)
            for f in failures:
                print(f"  - {f}", file=sys.stderr)
            return 1
        print("\nGATE PASSED — no detection regression vs the baseline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
