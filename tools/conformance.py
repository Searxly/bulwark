"""Prove the three implementations agree.

Bulwark's README claims Python, TypeScript and Swift "produce identical
verdicts". That is a strong claim about three separately hand-written regex
engines, three Unicode stacks and three HTML parsers — so it should be tested,
not asserted.

This runs the *same* corpus bytes through all three drivers and diffs the
verdicts. Any divergence is a bug in at least one of them.

    python3 tools/conformance.py                 # all available languages
    python3 tools/conformance.py --only py,ts    # skip a slow toolchain
    python3 tools/conformance.py --json
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

import corpus as corpus_mod  # noqa: E402

REPO = corpus_mod.REPO_ROOT
MERGED = corpus_mod.CORPUS_DIR / "corpus.jsonl"

# Fields compared across languages, in report order. `score` is compared with a
# tolerance; everything else must match exactly.
EXACT_FIELDS = ("injected", "risk", "patterns")
SCORE_TOLERANCE = 1e-4


class DriverUnavailable(RuntimeError):
    pass


def _run(cmd: List[str], cwd: Path, stdin_path: Path) -> str:
    with stdin_path.open("rb") as fh:
        proc = subprocess.run(cmd, cwd=cwd, stdin=fh, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"driver failed: {' '.join(cmd)}\n"
            f"{proc.stderr.decode('utf-8', 'replace')[-4000:]}"
        )
    return proc.stdout.decode("utf-8")


def run_python(merged: Path) -> Dict[str, dict]:
    out = _run([sys.executable, str(REPO / "tools/drivers/scan_py.py")], REPO, merged)
    return {json.loads(l)["id"]: json.loads(l) for l in out.splitlines() if l.strip()}


def run_typescript(merged: Path) -> Dict[str, dict]:
    ts_dir = REPO / "typescript"
    if not (ts_dir / "node_modules").is_dir():
        raise DriverUnavailable("typescript/node_modules missing — run `npm install` in typescript/")
    if shutil.which("npx") is None:
        raise DriverUnavailable("npx not found on PATH")
    out = _run(
        ["npx", "--no-install", "tsx", str(REPO / "tools/drivers/scan_ts.ts")],
        ts_dir,
        merged,
    )
    return {json.loads(l)["id"]: json.loads(l) for l in out.splitlines() if l.strip()}


def run_swift(merged: Path) -> Dict[str, dict]:
    if shutil.which("swift") is None:
        raise DriverUnavailable("swift not found on PATH")
    build = subprocess.run(
        ["swift", "build", "-c", "release", "--product", "bulwark-conformance"],
        cwd=REPO, capture_output=True,
    )
    if build.returncode != 0:
        raise RuntimeError(
            "swift build failed:\n" + build.stderr.decode("utf-8", "replace")[-4000:]
        )
    binary = REPO / ".build" / "release" / "bulwark-conformance"
    out = _run([str(binary)], REPO, merged)
    return {json.loads(l)["id"]: json.loads(l) for l in out.splitlines() if l.strip()}


DRIVERS = {
    "py": ("Python", run_python),
    "ts": ("TypeScript", run_typescript),
    "swift": ("Swift", run_swift),
}


def compare(reference: str, results: Dict[str, Dict[str, dict]]) -> List[dict]:
    """Diff every non-reference language against the reference implementation."""
    ref = results[reference]
    divergences: List[dict] = []
    for lang, rows in results.items():
        if lang == reference:
            continue
        missing = sorted(set(ref) - set(rows))
        extra = sorted(set(rows) - set(ref))
        if missing:
            divergences.append({"lang": lang, "id": "-", "field": "coverage",
                                "reference": f"{len(missing)} cases", "actual": "absent",
                                "detail": ", ".join(missing[:10])})
        if extra:
            divergences.append({"lang": lang, "id": "-", "field": "coverage",
                                "reference": "absent", "actual": f"{len(extra)} extra cases",
                                "detail": ", ".join(extra[:10])})
        for case_id in sorted(set(ref) & set(rows)):
            a, b = ref[case_id], rows[case_id]
            for field in EXACT_FIELDS:
                if a.get(field) != b.get(field):
                    divergences.append({
                        "lang": lang, "id": case_id, "field": field,
                        "reference": a.get(field), "actual": b.get(field),
                        "detail": "",
                    })
            if abs(float(a.get("score", 0)) - float(b.get("score", 0))) > SCORE_TOLERANCE:
                divergences.append({
                    "lang": lang, "id": case_id, "field": "score",
                    "reference": a.get("score"), "actual": b.get("score"), "detail": "",
                })
    return divergences


def format_divergences(divergences: List[dict], results: Dict[str, Dict[str, dict]]) -> str:
    lines = ["Bulwark cross-language conformance", "=" * 60]
    for lang, rows in results.items():
        lines.append(f"  {DRIVERS[lang][0]:<12} {len(rows)} cases graded")
    lines.append("")
    if not divergences:
        lines.append("  ✓ all implementations agree on every case")
        return "\n".join(lines)

    lines.append(f"  ✗ {len(divergences)} divergence(s)")
    by_field: Dict[Tuple[str, str], int] = {}
    for d in divergences:
        by_field[(d["lang"], d["field"])] = by_field.get((d["lang"], d["field"]), 0) + 1
    for (lang, field), n in sorted(by_field.items()):
        lines.append(f"    {lang}/{field}: {n}")
    lines.append("")
    for d in divergences[:40]:
        lines.append(
            f"    [{d['lang']}] {d['id']:<10} {d['field']:<10} "
            f"reference={d['reference']!r} actual={d['actual']!r} {d['detail']}"
        )
    if len(divergences) > 40:
        lines.append(f"    … and {len(divergences) - 40} more")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", default="py,ts,swift", help="comma-separated subset of py,ts,swift")
    ap.add_argument("--reference", default="py", choices=sorted(DRIVERS))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--allow-missing", action="store_true",
                    help="skip languages whose toolchain is unavailable instead of failing")
    args = ap.parse_args()

    cases = corpus_mod.load()
    corpus_mod.export_jsonl(cases, MERGED)

    wanted = [k.strip() for k in args.only.split(",") if k.strip()]
    results: Dict[str, Dict[str, dict]] = {}
    skipped: Dict[str, str] = {}
    for key in wanted:
        if key not in DRIVERS:
            print(f"unknown language {key!r}", file=sys.stderr)
            return 2
        name, fn = DRIVERS[key]
        try:
            results[key] = fn(MERGED)
        except DriverUnavailable as exc:
            if key == args.reference or not args.allow_missing:
                print(f"{name} driver unavailable: {exc}", file=sys.stderr)
                return 2
            skipped[key] = str(exc)

    divergences = compare(args.reference, results)

    if args.json:
        print(json.dumps({
            "graded": {k: len(v) for k, v in results.items()},
            "skipped": skipped,
            "divergences": divergences,
        }, indent=2, ensure_ascii=False))
    else:
        print(format_divergences(divergences, results))
        for key, why in skipped.items():
            print(f"  (skipped {DRIVERS[key][0]}: {why})")

    return 1 if divergences else 0


if __name__ == "__main__":
    raise SystemExit(main())
