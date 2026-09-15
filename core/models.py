from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Iterable, Any
from core.heuristics import bytes_to_text

@dataclass(frozen=True)
class Candidate:
    text: str
    chain: tuple[str, ...]
    score: float

@dataclass(frozen=True)
class DecodeState:
    raw: bytes
    text: str
    chain: tuple[str, ...] = ()
    score: float = 0.0

    @classmethod
    def from_raw(cls, raw: bytes, chain: tuple[str, ...] = (), score: float = 0.0) -> "DecodeState":
        text = bytes_to_text(raw) or raw.decode("latin-1", errors="replace")
        return cls(raw=raw, text=text, chain=chain, score=score)

    def updated(
        self,
        raw: bytes | None = None,
        text: str | None = None,
        chain: tuple[str, ...] | None = None,
        score: float | None = None,
    ) -> "DecodeState":
        return DecodeState(
            raw=self.raw if raw is None else raw,
            text=self.text if text is None else text,
            chain=self.chain if chain is None else chain,
            score=self.score if score is None else score,
        )

DecoderFunc = Callable[[str], Any]
ProgressCallback = Callable[[int, int, int], None]
