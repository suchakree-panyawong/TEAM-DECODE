#!/usr/bin/env python3
"""TEAM-DECODE quality gate — run this before and after every change.

Stages:
  1. Unit regressions  (tests/test_regressions.py, unittest)
  2. System test       (tests/system_test.py — 35 simple + 3 chain cases)
  3. Benchmark smoke   (--smoke only — quick accuracy sample)

Usage:
  python run_tests.py            # fast gate (~seconds)
  python run_tests.py --smoke    # + benchmark sample (~1 min)

Exit code 0 = all green, 1 = something broke. Do not ship on red.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run(cmd: list[str], cwd: Path = ROOT) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def stage_unit_tests() -> bool:
    print("== [1/2] unit regressions ==")
    proc = run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"])
    print(proc.stdout.strip() or proc.stderr.strip())
    ok = proc.returncode == 0
    print(f"   -> {'PASS' if ok else 'FAIL'}")
    return ok


def stage_system_test() -> bool:
    print("== [2/2] system test ==")
    proc = run([sys.executable, str(ROOT / "tests" / "system_test.py")])
    if proc.returncode != 0:
        print(proc.stdout[-2000:] or proc.stderr[-2000:])
        print("   -> FAIL (system test crashed)")
        return False
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(proc.stdout[-2000:])
        print("   -> FAIL (could not parse system test output)")
        return False
    s = report["summary"]
    simple_ok = s["simple_passed"] == s["simple_cases"] and s["simple_cases"] > 0
    chain_ok = s["chain_passed"] == s["chain_cases"] and s["chain_cases"] > 0
    registry_ok = not s["missing_decoders"]
    print(f"   simple: {s['simple_passed']}/{s['simple_cases']}"
          f"  chain: {s['chain_passed']}/{s['chain_cases']}"
          f"  decoders: {s['available_decoders']}"
          f"  missing: {s['missing_decoders'] or 'none'}")
    for name, ok in (("simple", simple_ok), ("chain", chain_ok), ("registry", registry_ok)):
        if not ok:
            print(f"   -> FAIL ({name})")
            return False
    print("   -> PASS")
    return True


def stage_benchmark_smoke() -> bool:
    print("== [bonus] benchmark smoke (60 cases) ==")
    proc = run([sys.executable, str(ROOT / "benchmarks" / "benchmark_1000.py"),
                "--easy", "20", "--normal", "15", "--hard", "20", "--extreme", "5",
                "--workers", "4"])
    print(proc.stdout[-1500:] or proc.stderr[-1500:])
    try:
        report = json.loads((ROOT / "benchmarks" / "reports" / "benchmark_report.json").read_text(encoding="utf-8"))
        print(f"   smoke top1: {report['top1_pct']}% (informational — compare against your baseline)")
        return proc.returncode == 0
    except Exception as e:
        print(f"   -> could not read benchmark report: {e}")
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--smoke", action="store_true", help="also run a quick benchmark sample")
    args = ap.parse_args()

    ok = stage_unit_tests() and stage_system_test()
    if ok and args.smoke:
        ok = stage_benchmark_smoke()
    print("\nRESULT:", "ALL GREEN" if ok else "BROKEN — do not ship")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
