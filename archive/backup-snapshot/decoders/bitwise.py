from __future__ import annotations
import base64, binascii, re
from collections import Counter
from core.registry import register_decoder
from core.heuristics import bytes_to_text, score_text, ENGLISH_LETTER_FREQ

def add_base64_padding(value: str) -> str:
    return value + ("=" * ((4 - len(value) % 4) % 4))

XOR_SINGLEBYTE_MIN_SCORE = 15.0

@register_decoder(name="xor_singlebyte", category="bitwise")
def decode_xor_singlebyte(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value); raw = None
    if re.fullmatch(r"[0-9A-Fa-f]+", compact) and len(compact) % 2 == 0 and len(compact) >= 6:
        try: raw = bytes.fromhex(compact)
        except ValueError: pass
    if raw is None and re.fullmatch(r"[A-Za-z0-9+/]+=*", compact) and len(compact) >= 8:
        try: raw = base64.b64decode(add_base64_padding(compact), validate=True)
        except (binascii.Error, ValueError): pass
    if raw is None or len(raw) < 4: return None
    best_text, best_score = None, -999.0
    for key in range(1, 256):
        text = bytes_to_text(bytes(b ^ key for b in raw))
        if text is None: continue
        s = score_text(text)
        if s > best_score: best_text, best_score = text, s
    return best_text if best_text is not None and best_score >= XOR_SINGLEBYTE_MIN_SCORE else None

MULTI_XOR_MIN_LENGTH, MULTI_XOR_MIN_KEYLEN, MULTI_XOR_MAX_KEYLEN = 40, 2, 8
MULTI_XOR_IC_THRESHOLD, MULTI_XOR_MIN_BYTES_PER_COLUMN, MULTI_XOR_FINAL_SCORE_THRESHOLD = 0.045, 18, 16.0

def _index_of_coincidence(data: bytes) -> float:
    n = len(data)
    if n < 2: return 0.0
    return sum(c * (c-1) for c in Counter(data).values()) / (n * (n-1))

def _shortlist_xor_multikey_lengths(raw: bytes, max_keylen: int) -> list[int]:
    candidates = []
    for keylen in range(MULTI_XOR_MIN_KEYLEN, max_keylen + 1):
        if len(raw) < keylen * MULTI_XOR_MIN_BYTES_PER_COLUMN: continue
        column_ics = [_index_of_coincidence(raw[i::keylen]) for i in range(keylen) if len(raw[i::keylen]) >= 2]
        if column_ics and (sum(column_ics) / len(column_ics)) >= MULTI_XOR_IC_THRESHOLD: candidates.append(keylen)
    return candidates

def _crack_xor_multikey_column(column: bytes) -> int:
    best_key, best_score = 0, float("-inf")
    for key in range(256):
        score = 0.0
        for b in column:
            ch = chr(b ^ key)
            if ch == " ": score += 2.5
            elif "a" <= ch <= "z": score += ENGLISH_LETTER_FREQ.get(ch, 0.05)
            elif "A" <= ch <= "Z": score += ENGLISH_LETTER_FREQ.get(ch.lower(), 0.05) * 0.8
            elif ch in ".,!?'\"-_{}": score += 0.4
            elif 32 <= (b ^ key) < 127: score += 0.05
            else: score -= 3.0
        if score > best_score: best_score, best_key = score, key
    return best_key

@register_decoder(name="xor_multikey", category="bitwise")
def decode_xor_multikey(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value); raw = None
    if re.fullmatch(r"[0-9A-Fa-f]+", compact) and len(compact) % 2 == 0 and len(compact) >= MULTI_XOR_MIN_LENGTH:
        try: raw = bytes.fromhex(compact)
        except ValueError: pass
    if raw is None and re.fullmatch(r"[A-Za-z0-9+/]+=*", compact) and len(compact) >= MULTI_XOR_MIN_LENGTH:
        try: raw = base64.b64decode(add_base64_padding(compact), validate=True)
        except (binascii.Error, ValueError): pass
    if raw is None and len(compact) >= MULTI_XOR_MIN_LENGTH:
        if score_text(value) < 15.0:
            try: raw = value.encode("latin-1")
            except UnicodeEncodeError: pass
    if raw is None or len(raw) < MULTI_XOR_MIN_LENGTH: return None
    keylen_candidates = _shortlist_xor_multikey_lengths(raw, MULTI_XOR_MAX_KEYLEN)
    if not keylen_candidates: return None
    best_text, best_score = None, float("-inf")
    for keylen in keylen_candidates:
        key = bytes(_crack_xor_multikey_column(raw[i::keylen]) for i in range(keylen))
        if all(k == 0 for k in key): continue
        text = bytes_to_text(bytes(b ^ key[i % keylen] for i, b in enumerate(raw)))
        if text is None: continue
        s = score_text(text)
        if s > best_score: best_text, best_score = text, s
    return best_text if best_text is not None and best_score >= MULTI_XOR_FINAL_SCORE_THRESHOLD else None
