from __future__ import annotations
import base64, bz2, gzip, importlib.util, lzma, re, zlib
from typing import Callable
from core.registry import register_decoder
from core.heuristics import _log_debug, bytes_to_text

if importlib.util.find_spec("zstandard") is not None:
    import zstandard as zstd
elif importlib.util.find_spec("zstd") is not None:
    import zstd
else:
    zstd = None

def add_base64_padding(value: str) -> str:
    return value + ("=" * ((4 - len(value) % 4) % 4))

def _decompress_payload(value: str, fn: Callable[[bytes], bytes], name: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if re.fullmatch(r"[0-9A-Fa-f]+", compact) and len(compact) % 2 == 0:
        try:
            res = bytes_to_text(fn(bytes.fromhex(compact)))
            if res is not None: return res
        except Exception as e: _log_debug(f"{name}: hex path failed: {e!r}")
    if re.fullmatch(r"[A-Za-z0-9+/]+=*", compact):
        try:
            res = bytes_to_text(fn(base64.b64decode(add_base64_padding(compact))))
            if res is not None: return res
        except Exception as e: _log_debug(f"{name}: base64 path failed: {e!r}")
    try:
        res = bytes_to_text(fn(value.encode("latin-1")))
        if res is not None: return res
    except Exception as e: _log_debug(f"{name}: raw bytes path failed: {e!r}")
    return None

@register_decoder(name="gzip", category="compression")
def decode_gzip(v: str) -> str | None:
    return _decompress_payload(v, gzip.decompress, "decode_gzip")

@register_decoder(name="bzip2", category="compression")
def decode_bzip2(v: str) -> str | None:
    return _decompress_payload(v, bz2.decompress, "decode_bzip2")

@register_decoder(name="xz", category="compression")
def decode_xz(v: str) -> str | None:
    return _decompress_payload(v, lzma.decompress, "decode_xz")

@register_decoder(name="zstd", category="compression")
def decode_zstd(v: str) -> str | None:
    if zstd is None: return None
    decomp_fn = (lambda d: zstd.decompress(d)) if hasattr(zstd, "decompress") else (lambda d: zstd.ZstdDecompressor().decompress(d))
    return _decompress_payload(v, decomp_fn, "decode_zstd")

@register_decoder(name="zlib", category="compression")
def decode_zlib(v: str) -> str | None:
    def _zlib(d: bytes) -> bytes:
        try: return zlib.decompress(d)
        except Exception: return zlib.decompress(d, wbits=-15)
    return _decompress_payload(v, _zlib, "decode_zlib")
