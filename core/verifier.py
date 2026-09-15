#!/usr/bin/env python3
"""Lightweight AI verifier for TEAM-DECODE.

Re-ranks the top candidates produced by core.engine.auto_decode with a
logistic-regression model trained on generated benchmark data. The model is
tiny (a feature vector + weight vector) so inference adds ~milliseconds.

Training data is produced by benchmarks/gen_training_data.py and the learned
weights are stored in core/verifier_weights.json next to this file.
"""
from __future__ import annotations

import json
import math
import re
from pathlib import Path

import numpy as np

from .heuristics import _score_parts, is_always_succeeds_scheme

WEIGHTS_PATH = Path(__file__).resolve().parent / "verifier_weights.json"
GBM_PATH = Path(__file__).resolve().parent / "verifier_gbm.pkl"

FEATURE_NAMES = [
    # score_text components
    "pr", "ar", "wb", "fb", "cs", "lb", "ep", "cp", "db", "tb",
    "alpha_bonus", "ngram",
    # text shape
    "log_len", "has_spaces", "digit_ratio", "upper_ratio", "vowel_ratio",
    "unique_ratio", "is_ascii", "space_ratio", "punct_ratio",
    # chain shape
    "chain_len", "substitution_steps", "validated_steps",
    "has_compression", "has_xor", "engine_rank0", "engine_score_norm",
]

_VOWELS = set("aeiouyAEIOUY")


def extract_features(text: str, chain: tuple[str, ...], engine_score: float,
                     engine_rank: int) -> list[float]:
    pr, ar, wb, fb, cs, lb, ep, cp, db, tb, alpha_bonus, ng = _score_parts(text)
    n = max(len(text), 1)
    letters = sum(c.isalpha() for c in text)
    return [
        pr, ar, wb, fb, cs, lb, -ep, -cp, db, tb, alpha_bonus, ng,
        math.log(len(text) + 1),
        1.0 if " " in text.strip() else 0.0,
        sum(c.isdigit() for c in text) / n,
        sum(c.isupper() for c in text) / n,
        sum(c in _VOWELS for c in text) / max(letters, 1),
        len(set(text)) / n,
        1.0 if text.isascii() else 0.0,
        sum(c == " " for c in text) / n,
        sum(c in "!?.,:;'\"-_{}[]()/&%$#@*+=" for c in text) / n,
        len(chain),
        sum(1 for s in chain if is_always_succeeds_scheme(s)),
        len(chain) - sum(1 for s in chain if is_always_succeeds_scheme(s)),
        1.0 if any(s in {"gzip", "zlib", "bzip2", "xz", "zstd"} for s in chain) else 0.0,
        1.0 if any("xor" in s for s in chain) else 0.0,
        1.0 if engine_rank == 0 else 0.0,
        engine_score / 30.0,
    ]


class VerifierRanker:
    """Re-ranker over engine candidates: small gradient boosting when
    available, logistic weights as light fallback, engine order otherwise."""

    def __init__(self):
        self.weights: np.ndarray | None = None
        self.bias = 0.0
        self.mean: np.ndarray | None = None
        self.std: np.ndarray | None = None
        self.gbm = None

    @property
    def available(self) -> bool:
        return self.gbm is not None or self.weights is not None

    def score(self, features: list[float]) -> float:
        x = (np.asarray(features, dtype=float) - self.mean) / self.std
        return float(x @ self.weights + self.bias)

    def score_many(self, features: list[list[float]]) -> np.ndarray:
        if self.gbm is not None:
            return self.gbm.predict_proba(np.asarray(features, dtype=float))[:, 1]
        X = (np.asarray(features, dtype=float) - self.mean) / self.std
        return X @ self.weights + self.bias

    def rerank(self, candidates: list, top_k: int = 30) -> list:
        """Return candidates sorted by verifier score (stable on engine order)."""
        if not self.available or not candidates:
            return candidates
        head = candidates[:top_k]
        feats = [extract_features(c.text, c.chain, c.score, rank)
                 for rank, c in enumerate(head)]
        scores = self.score_many(feats)
        order = sorted(range(len(head)), key=lambda i: (-scores[i], i))
        return [head[i] for i in order] + candidates[top_k:]

    # ---------------------------------------------------------------- training

    @classmethod
    def _load_xy(cls, dataset_path: str | Path):
        X, y = [], []
        with open(dataset_path, encoding="utf-8") as f:
            for line in f:
                row = json.loads(line)
                for cand in row["candidates"]:
                    X.append(cand["features"])
                    y.append(cand["label"])
        return np.asarray(X, dtype=float), np.asarray(y, dtype=int)

    @classmethod
    def train(cls, dataset_path: str | Path) -> tuple["VerifierRanker", dict]:
        """Train GBM (primary) + logistic (fallback) on a JSONL dataset."""
        from sklearn.ensemble import GradientBoostingClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.preprocessing import StandardScaler

        X, y = cls._load_xy(dataset_path)
        scaler = StandardScaler().fit(X)
        Xs = scaler.transform(X)
        clf = LogisticRegression(max_iter=2000, class_weight="balanced")
        clf.fit(Xs, y)
        gbm = GradientBoostingClassifier(n_estimators=120, max_depth=3, learning_rate=0.1)
        gbm.fit(X, y)

        model = cls()
        model.gbm = gbm
        model.weights = clf.coef_[0]
        model.bias = float(clf.intercept_[0])
        model.mean = scaler.mean_
        model.std = scaler.scale_
        info = {
            "n_candidates": len(y),
            "n_positive": int(y.sum()),
            "logistic_train_accuracy": float(clf.score(Xs, y)),
            "gbm_train_accuracy": float(gbm.score(X, y)),
        }
        return model, info

    def save(self, weights_path: str | Path = WEIGHTS_PATH, gbm_path: str | Path = GBM_PATH) -> None:
        import pickle

        payload = {
            "feature_names": FEATURE_NAMES,
            "weights": self.weights.tolist(),
            "bias": self.bias,
            "mean": self.mean.tolist(),
            "std": self.std.tolist(),
        }
        Path(weights_path).write_text(json.dumps(payload), encoding="utf-8")
        if self.gbm is not None:
            with open(gbm_path, "wb") as f:
                pickle.dump(self.gbm, f)

    @classmethod
    def load(cls, weights_path: str | Path = WEIGHTS_PATH, gbm_path: str | Path = GBM_PATH) -> "VerifierRanker":
        model = cls()
        wp, gp = Path(weights_path), Path(gbm_path)
        if wp.exists():
            payload = json.loads(wp.read_text(encoding="utf-8"))
            model.weights = np.asarray(payload["weights"], dtype=float)
            model.bias = payload["bias"]
            model.mean = np.asarray(payload["mean"], dtype=float)
            model.std = np.asarray(payload["std"], dtype=float)
        if gp.exists():
            try:
                import pickle

                with open(gp, "rb") as f:
                    model.gbm = pickle.load(f)
            except Exception:
                model.gbm = None
        return model


if __name__ == "__main__":
    import sys

    src = sys.argv[1] if len(sys.argv) > 1 else "benchmarks/reports/verifier_train.jsonl"
    model, info = VerifierRanker.train(src)
    model.save()
    print(json.dumps(info, indent=2))
    print(f"saved -> {WEIGHTS_PATH}, {GBM_PATH}")
