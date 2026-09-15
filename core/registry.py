from __future__ import annotations
from typing import Callable, Any

# Keyed by decoder name so re-registration (e.g. module reload) always
# reflects the latest function for that name instead of being silently
# skipped or duplicated. This makes registration idempotent regardless
# of reload order/count.
_DECODERS_BY_NAME: dict[str, dict[str, Any]] = {}

def register_decoder(name: str, category: str = "general"):
    """Decorator to register a decoder function into the registry.

    Re-registering the same name (e.g. from a module reload) overwrites
    the previous entry rather than being skipped, so the registry always
    reflects the currently-imported code. Order of first-registration is
    preserved for stable iteration order.
    """
    def decorator(func: Callable[[str], Any]):
        _DECODERS_BY_NAME[name] = {
            "name": name,
            "category": category,
            "func": func
        }
        return func
    return decorator

def get_all_decoders() -> list[dict[str, Any]]:
    """Return all registered decoders (rebuilt fresh from the name-keyed
    store each call, so it always reflects the current registration state)."""
    return list(_DECODERS_BY_NAME.values())