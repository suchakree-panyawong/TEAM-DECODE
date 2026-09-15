from __future__ import annotations
from typing import Callable, Any

DECODER_REGISTRY: list[dict[str, Any]] = []

def register_decoder(name: str, category: str = "general"):
    """Decorator to register a decoder function into DECODER_REGISTRY."""
    def decorator(func: Callable[[str], Any]):
        DECODER_REGISTRY.append({
            "name": name,
            "category": category,
            "func": func
        })
        return func
    return decorator

def get_all_decoders() -> list[dict[str, Any]]:
    """Return all registered decoders."""
    return DECODER_REGISTRY
