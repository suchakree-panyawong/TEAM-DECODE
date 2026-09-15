from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Iterable, Any

@dataclass(frozen=True)
class Candidate:
    text: str
    chain: tuple[str, ...]
    score: float

DecoderFunc = Callable[[str], Any]
ProgressCallback = Callable[[int, int, int], None]
