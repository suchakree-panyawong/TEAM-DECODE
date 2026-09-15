#!/usr/bin/env python3
"""Generate training data for the AI verifier.

Runs benchmark-style cases through auto_decode, keeps the top-K candidates
per case with extracted features, and labels the candidate that matches the
expected plaintext. Train/val split by seed: training cases never reuse the
benchmark seed (42) so evaluation stays honest.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import decoders  # noqa: F401
from core.engine import auto_decode
from core.verifier import extract_features

sys.path.insert(0, str(Path(__file__).resolve().parent))
import benchmark_1000 as bm  # noqa: E402


def _init(depth: int, beam: int, topk: int):
    global _CFG
    _CFG = {"depth": depth, "beam": beam, "topk": topk}


def _run_case(case: dict) -> dict:
    cfg = _CFG
    try:
        cands = auto_decode(case["input"], max_depth=cfg["depth"], beam_size=cfg["beam"])
    except Exception:
        cands = []
    rows = []
    found = False
    for rank, cand in enumerate(cands[: cfg["topk"]]):
        label = 0
        if not found and bm.match(cand.text, case["expected"], case["mode"]):
            label, found = 1, True
        rows.append({
            "features": extract_features(cand.text, cand.chain, cand.score, rank),
            "label": label,
            "text": cand.text[:120],
            "chain": list(cand.chain),
        })
    return {"expected": case["expected"][:120], "found": found, "candidates": rows}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--easy", type=int, default=80)
    ap.add_argument("--normal", type=int, default=80)
    ap.add_argument("--hard", type=int, default=150)
    ap.add_argument("--extreme", type=int, default=60)
    ap.add_argument("--depth", type=int, default=8)
    ap.add_argument("--beam", type=int, default=40)
    ap.add_argument("--topk", type=int, default=30)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--out", type=str, required=True)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    counts = {"easy": args.easy, "normal": args.normal, "hard": args.hard, "extreme": args.extreme}
    cases = bm.build_cases(rng, counts)
    print(f"built {len(cases)} cases (seed={args.seed})", flush=True)

    t0 = time.perf_counter()
    n_found = 0
    with open(args.out, "w", encoding="utf-8") as f, \
         ProcessPoolExecutor(max_workers=args.workers, initializer=_init,
                             initargs=(args.depth, args.beam, args.topk)) as ex:
        for i, row in enumerate(ex.map(_run_case, cases, chunksize=1), 1):
            n_found += row["found"]
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            if i % 50 == 0:
                print(f"[{i}/{len(cases)}] found={n_found}/{i} elapsed={time.perf_counter()-t0:.0f}s", flush=True)
    print(f"done: {n_found}/{len(cases)} cases have the answer in top-{args.topk}", flush=True)


if __name__ == "__main__":
    main()
