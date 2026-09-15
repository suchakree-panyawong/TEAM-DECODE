#!/usr/bin/env python3
"""Compare verifier styles on held-out validation data.

Styles:
  A. engine      — current scoring only (baseline)
  B. logistic    — logistic regression re-rank over engine candidates
  C. gbm         — small gradient boosting re-rank (heavier, for comparison)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sklearn.ensemble import GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler


def load(path: str) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            rows.append(json.loads(line))
    return rows


def topk_accuracy(rows: list[dict], k: int, rank_fn) -> float:
    hits = 0
    for row in rows:
        if not row["found"]:
            continue
        order = rank_fn(row["candidates"])
        if any(c["label"] == 1 for c in order[:k]):
            hits += 1
    return 100.0 * hits / max(len(rows), 1)


def main() -> None:
    train_path = sys.argv[1] if len(sys.argv) > 1 else "benchmarks/reports/verifier_train.jsonl"
    val_path = sys.argv[2] if len(sys.argv) > 2 else "benchmarks/reports/verifier_val.jsonl"
    train, val = load(train_path), load(val_path)

    X, y = [], []
    for row in train:
        for c in row["candidates"]:
            X.append(c["features"]); y.append(c["label"])
    X, y = np.asarray(X), np.asarray(y)
    scaler = StandardScaler().fit(X)
    Xs = scaler.transform(X)

    log = LogisticRegression(max_iter=2000, class_weight="balanced").fit(Xs, y)
    gbm = GradientBoostingClassifier(n_estimators=120, max_depth=3, learning_rate=0.1).fit(X, y)

    def engine_rank(cands):
        return cands  # already in engine order

    def logistic_rank(cands):
        F = scaler.transform(np.asarray([c["features"] for c in cands]))
        s = log.decision_function(F)
        return [c for _, _, c in sorted(zip(-s, range(len(cands)), cands), key=lambda t: (t[0], t[1]))]

    def gbm_rank(cands):
        F = np.asarray([c["features"] for c in cands])
        s = gbm.predict_proba(F)[:, 1]
        return [c for _, _, c in sorted(zip(-s, range(len(cands)), cands), key=lambda t: (t[0], t[1]))]

    print(f"train cases: {len(train)} | val cases: {len(val)} | "
          f"val with answer present: {sum(r['found'] for r in val)}/{len(val)}")
    for name, fn in [("A engine (baseline)", engine_rank), ("B logistic", logistic_rank), ("C gbm", gbm_rank)]:
        t1 = topk_accuracy(val, 1, fn)
        t3 = topk_accuracy(val, 3, fn)
        print(f"{name:22s} top1={t1:5.1f}%  top3={t3:5.1f}%")


if __name__ == "__main__":
    main()
