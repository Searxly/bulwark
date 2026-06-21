#!/usr/bin/env python3
"""Zero-dependency test runner.

Discovers ``test_*`` functions in ``tests/`` and runs them, so the suite works
even without pytest installed. CI uses pytest; this is the local fallback::

    python run_tests.py
"""

from __future__ import annotations

import importlib.util
import os
import sys
import traceback

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))
TESTS_DIR = os.path.join(ROOT, "tests")


def load_module(path: str):
    name = "t_" + os.path.splitext(os.path.basename(path))[0]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    files = sorted(f for f in os.listdir(TESTS_DIR) if f.startswith("test_") and f.endswith(".py"))
    passed = failed = 0
    failures = []
    for fname in files:
        mod = load_module(os.path.join(TESTS_DIR, fname))
        tests = sorted(n for n in dir(mod) if n.startswith("test_") and callable(getattr(mod, n)))
        for tname in tests:
            try:
                getattr(mod, tname)()
                passed += 1
                print(f"  PASS  {fname}::{tname}")
            except Exception:  # noqa: BLE001
                failed += 1
                failures.append((fname, tname, traceback.format_exc()))
                print(f"  FAIL  {fname}::{tname}")

    print("\n" + "=" * 60)
    print(f"{passed} passed, {failed} failed")
    for fname, tname, tb in failures:
        print("\n" + "-" * 60)
        print(f"FAILURE: {fname}::{tname}")
        print(tb)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
