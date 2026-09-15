from __future__ import annotations
import math, re
from collections import Counter
from typing import Callable, Iterable
from .models import Candidate
from .registry import get_all_decoders
from .heuristics import (
    _log_debug, normalize_input, score_text, gets_validated_bonus,
    url_legibility_bonus, unicode_legibility_bonus, substitution_legibility_bonus,
    is_always_succeeds_scheme, total_substitution_count, trailing_substitution_run,
    total_weak_chain_count, is_effectively_binary, has_full_flag_pattern,
    flag_context_is_plausible, has_residual_encoding_artifact,
    VALIDATED_DECODE_BONUS, DENSE_LOW_CONFIDENCE_SCHEMES, MIN_LENGTH_FOR_DENSE_BONUS,
    ALWAYS_SUCCEEDS_STEP_PENALTY, FLAG_FOUND_OVERRIDE_BONUS,
    ONCE_PER_CHAIN_SCHEMES, MAX_TOTAL_SUBSTITUTION, WEAK_CHAIN_CAP_SCHEMES,
    MAX_WEAK_CHAIN_LENGTH, MAX_CONSECUTIVE_SUBSTITUTION, DEFAULT_BEAM_SIZE,
    PLAINTEXT_SHIELD_THRESHOLD, PLAINTEXT_SHIELD_BONUS, MIN_VALIDATED_BONUS_LENGTH,
    thai_confidence_bonus, decode_evidence, EVIDENCE_GATED_SCHEMES
)

def decode_once(value: str, chain: tuple[str, ...] = ()) -> Iterable[tuple[str, str]]:
    for item in get_all_decoders():
        name = item["name"]
        func = item["func"]
        
        if name in ONCE_PER_CHAIN_SCHEMES and name in chain:
            continue
        if is_always_succeeds_scheme(name) and total_substitution_count(chain) >= MAX_TOTAL_SUBSTITUTION:
            continue
        if name in WEAK_CHAIN_CAP_SCHEMES and total_weak_chain_count(chain) >= MAX_WEAK_CHAIN_LENGTH:
            continue
        if is_always_succeeds_scheme(name) and trailing_substitution_run(chain) >= MAX_CONSECUTIVE_SUBSTITUTION:
            continue
            
        try:
            res = func(value)
        except Exception as e:
            _log_debug(f"decode_once: decoder {name!r} raised: {e!r}")
            continue
            
        if not res:
            continue
            
        if isinstance(res, list):
            for sub_name, decoded in res:
                if decoded:
                    decoded_str = decoded.strip()
                    if decoded_str and decoded_str != value:
                        yield sub_name, decoded_str
        elif isinstance(res, str):
            decoded_str = res.strip()
            if decoded_str and decoded_str != value:
                yield name, decoded_str

def auto_decode_beam_search(
    value: str,
    max_depth: int = 15,
    beam_size: int = DEFAULT_BEAM_SIZE,
    progress_callback: Callable[[int, int, int], None] | None = None,
    allowed_schemes: set[str] | None = None,
) -> list[Candidate]:
    start = normalize_input(value)
    best: dict[str, Candidate] = {start: Candidate(text=start, chain=(), score=score_text(start))}
    frontier = [best[start]]

    if has_full_flag_pattern(start) and flag_context_is_plausible(start):
        if not has_residual_encoding_artifact(start):
            return sorted(best.values(), key=lambda item: (item.score, -len(item.chain)), reverse=True)
        best[start] = Candidate(text=start, chain=(), score=best[start].score + FLAG_FOUND_OVERRIDE_BONUS - 10.0)
        frontier = [best[start]]
    elif best[start].score >= PLAINTEXT_SHIELD_THRESHOLD:
        # Input already reads as natural text: shield it so speculative
        # rot/xor chains cannot outrank the untouched start candidate.
        best[start] = Candidate(text=start, chain=(), score=best[start].score + PLAINTEXT_SHIELD_BONUS)
        frontier = [best[start]]
        
    for depth_index in range(max_depth):
        if progress_callback is not None:
            try:
                progress_callback(depth_index, max_depth, len(best))
            except Exception as e:
                _log_debug(f"auto_decode: progress_callback raised: {e!r}")
                
        next_frontier: list[Candidate] = []
        for candidate in frontier:
            for scheme, decoded in decode_once(candidate.text, candidate.chain):
                if allowed_schemes is not None and scheme not in allowed_schemes:
                    continue
                if decoded in best:
                    continue
                if "\ufffd" in decoded:
                    continue
                base_score = score_text(decoded)
                bonus = 0.0
                if gets_validated_bonus(scheme):
                    # A "validated" decode only earns its bonus when the output
                    # is clean printable text: no mojibake, no control bytes,
                    # and — for compression — actual textual evidence.
                    clean_text = all(ch.isprintable() or ch in "\n\r\t" for ch in decoded)
                    script_plausible = decoded.isascii() or thai_confidence_bonus(decoded) > 0
                    evidence_ok = (scheme not in EVIDENCE_GATED_SCHEMES
                                   or decode_evidence(decoded))
                    if (clean_text and script_plausible and evidence_ok
                            and not (scheme in DENSE_LOW_CONFIDENCE_SCHEMES and len(decoded) < MIN_LENGTH_FOR_DENSE_BONUS)
                            and len(decoded) >= MIN_VALIDATED_BONUS_LENGTH):
                        bonus += VALIDATED_DECODE_BONUS
                    bonus += url_legibility_bonus(scheme, decoded) + unicode_legibility_bonus(scheme, decoded)
                else:
                    if scheme in {"base36", "base58", "base62"}:
                        if len(decoded) >= 6 and any(ch.isalpha() for ch in decoded) and not is_effectively_binary(decoded) and ("_" in decoded or "{" in decoded or decoded.isalnum()):
                            bonus += VALIDATED_DECODE_BONUS
                    else:
                        bonus += substitution_legibility_bonus(scheme, decoded)
                new_chain = candidate.chain + (scheme,)
                chain_penalty = (
                    total_substitution_count(new_chain) * ALWAYS_SUCCEEDS_STEP_PENALTY
                    + max(0, len(new_chain) - 1) * 0.75
                )
                new_candidate = Candidate(text=decoded, chain=new_chain, score=base_score + bonus - chain_penalty)
                best[decoded] = new_candidate
                next_frontier.append(new_candidate)
                
                if has_full_flag_pattern(decoded) and flag_context_is_plausible(decoded):
                    override_bonus = FLAG_FOUND_OVERRIDE_BONUS - (10.0 if has_residual_encoding_artifact(decoded) else 0.0)
                    winning_candidate = Candidate(text=new_candidate.text, chain=new_candidate.chain, score=new_candidate.score + override_bonus)
                    best[decoded] = winning_candidate
                    next_frontier[-1] = winning_candidate
                    
        if not next_frontier:
            break
        frontier = sorted(next_frontier, key=lambda item: item.score, reverse=True)[:beam_size]
        
    if progress_callback is not None:
        try:
            progress_callback(max_depth, max_depth, len(best))
        except Exception as e:
            _log_debug(f"auto_decode: final progress_callback raised: {e!r}")
            
    return sorted(best.values(), key=lambda item: (item.score, -len(item.chain)), reverse=True)

auto_decode = auto_decode_beam_search

def railfence_decode(text: str, rails: int) -> str | None:
    if rails < 2 or rails >= max(len(text), 2): return None
    pattern = list(range(rails)) + list(range(rails-2, 0, -1))
    if not pattern: return None
    rail_index = [pattern[i % len(pattern)] for i in range(len(text))]
    counts = Counter(rail_index); slots = {r: [] for r in range(rails)}; pos = 0
    for r in range(rails):
        for _ in range(counts.get(r, 0)): slots[r].append(text[pos]); pos += 1
    cursors = {r: 0 for r in range(rails)}; out = []
    for r in rail_index: out.append(slots[r][cursors[r]]); cursors[r] += 1
    return "".join(out)

def vigenere_decode(text: str, key: str) -> str | None:
    key = re.sub(r"[^A-Za-z]", "", key)
    if not key: return None
    key_upper, out, ki = key.upper(), [], 0
    for ch in text:
        if ch.isalpha():
            shift = ord(key_upper[ki % len(key_upper)]) - ord('A')
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base - shift) % 26 + base)); ki += 1
        else: out.append(ch)
    return "".join(out)

def columnar_decode(text: str, key_width: int) -> str | None:
    if key_width < 2 or key_width >= max(len(text), 2): return None
    n = len(text); num_rows = math.ceil(n / key_width)
    num_full_cols = n % key_width or key_width
    col_lengths = [num_rows if c < num_full_cols else num_rows-1 for c in range(key_width)]
    cols, pos = [], 0
    for length in col_lengths: cols.append(text[pos:pos+length]); pos += length
    out = []
    for r in range(num_rows):
        for c in range(key_width):
            if r < len(cols[c]): out.append(cols[c][r])
    return "".join(out)
