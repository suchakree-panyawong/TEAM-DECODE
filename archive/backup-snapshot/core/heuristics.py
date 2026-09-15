from __future__ import annotations
import base64, binascii, math, os, re, string, sys
from collections import Counter

PRINTABLE = set(string.printable)
ENGLISH_LETTER_FREQ = dict(zip("etaoinshrdlcumwfgypbvkjxqz",
    [12.70,9.06,8.17,7.51,6.97,6.75,6.33,6.09,5.99,4.25,4.03,2.78,2.76,2.41,2.36,2.23,2.02,1.97,1.93,1.29,0.98,0.77,0.15,0.15,0.10,0.07]))

def _log_debug(msg: str) -> None:
    try:
        if os.environ.get("DEBUG_AUTO_DECODE"): print(msg, file=sys.stderr)
    except Exception: pass

def english_chi_squared(text: str) -> float | None:
    letters = [ch.lower() for ch in text if ch.isalpha()]; n = len(letters)
    if n < 5: return None
    counts = Counter(letters)
    return sum((counts.get(l, 0) - p / 100 * n) ** 2 / (p / 100 * n) for l, p in ENGLISH_LETTER_FREQ.items())

COMMON_WORDS = ("the","and","you","that","hello","world","password","secret","http","https","admin","root","user","hack","pwn","shell","exploit","payload","firewall","network","intrusion")
COMMON_ENGLISH_WORDS = frozenset("""the be to of and a in that have i it for not on with he as you do at this but
his by from they we say her she or an will my one all would there their what so up out if about who get which go me
when make can like time no just him know take people into year your good some could them see other than then now look
only come its over think also back after use two how our work first well way even new want because any these give day
most us is are was were been being am has had does did done going gone came goes gets got says said told asked needs
needed feels felt became leaving puts putting meant keeping lets letting began seems seemed helps helped shows showed
heard playing ran moved lived believed bringing happened wrote provides sitting stood loses lost met includes continued
sets learned changed leads led understands watched follows stopped creates spoke reads allows added spent grew opened
walked wins offered remembered loves considered appears bought waited served died sent expects built stays fell cut
reached killed remained suggested raised passed sold required reported decided pulled man woman child world school state
family student group country problem hand part place case week company system program question work government number
night point home water room mother area money story fact month lot study book eye job word business issue side kind
head house service friend father power hour game line end member law car city community name president team minute
idea body information parent face others level office door health person art war history party result morning reason
research girl guy moment air teacher force education network computer data file system code key secret password flag
ctf secure hack exploit payload base decode encode chain sample message value input output string simple encoded
encrypted hidden text unicode character alphabet standard multi single true false quick brown fox jumps over lazy dog
cat bird sun moon star sky blue red green yellow black white color love happy sad angry tired hungry tree flower rain
snow wind storm cloud river lake ocean sea mountain hill forest field farm animal plant fish horse cow pig sheep
chicken duck fruit apple orange banana bread milk juice coffee tea eat drink sleep wake today tomorrow yesterday
seashore shells shore beach sand wave swim bring vigilance constant requires security""".split())

CTF_MARKER_WORDS = {"flag","ctf","picoctf","htb"}
DICTIONARY_MIN_TOKENS, DICTIONARY_MAX_BONUS, DICTIONARY_MAX_PENALTY = 3, 4.0, 2.0
DICTIONARY_HIGH_RATIO, DICTIONARY_LOW_RATIO = 0.45, 0.12

def _dictionary_tokens(text: str) -> list[str]:
    return [tok.lower() for tok in re.findall(r"[A-Za-z']+", text) if len(tok) >= 3]

def dictionary_confidence_bonus(text: str) -> float:
    tokens = _dictionary_tokens(text)
    if len(tokens) < DICTIONARY_MIN_TOKENS: return 0.0
    ratio = sum(1 for t in tokens if t in COMMON_ENGLISH_WORDS or t in CTF_MARKER_WORDS) / len(tokens)
    if ratio >= DICTIONARY_HIGH_RATIO: return DICTIONARY_MAX_BONUS
    if ratio <= DICTIONARY_LOW_RATIO: return -DICTIONARY_MAX_PENALTY
    return -DICTIONARY_MAX_PENALTY + (ratio - DICTIONARY_LOW_RATIO) / (DICTIONARY_HIGH_RATIO - DICTIONARY_LOW_RATIO) * (DICTIONARY_MAX_BONUS + DICTIONARY_MAX_PENALTY)

THAI_CHAR_RANGE = (0x0E00, 0x0E7F)
THAI_CHAR_MIN_RATIO, THAI_RATIO_BONUS_SCALE, THAI_WORD_BONUS_CAP = 0.3, 10.0, 5
THAI_COMMON_WORDS = ("และ","คือ","ที่","ไม่","เป็น","การ","ใน","มี","ได้","จะ","ว่า","กับ","ของ","ให้","มา","ไป","แล้ว","นี้","นั้น","เขา","ฉัน","คุณ","เรา","ทำ","พูด","ดี","วัน","เวลา","คน","ธง","ความลับ","รหัส","ทดสอบ","ข้อความ")

def thai_char_ratio(text: str) -> float:
    if not text: return 0.0
    return sum(1 for ch in text if THAI_CHAR_RANGE[0] <= ord(ch) <= THAI_CHAR_RANGE[1]) / len(text)

def thai_confidence_bonus(text: str) -> float:
    ratio = thai_char_ratio(text)
    if ratio < THAI_CHAR_MIN_RATIO: return 0.0
    return ratio * THAI_RATIO_BONUS_SCALE + min(sum(1 for w in THAI_COMMON_WORDS if w in text), THAI_WORD_BONUS_CAP)

DEFAULT_MAX_DEPTH, DEFAULT_BEAM_SIZE, DEFAULT_CANDIDATE_COUNT = 15, 320, 5
MAX_CONSECUTIVE_SUBSTITUTION, MAX_TOTAL_SUBSTITUTION = 3, 3
ALWAYS_SUCCEEDS_STEP_PENALTY, FLAG_FOUND_OVERRIDE_BONUS = 2.0, 100.0

def normalize_input(value: str) -> str: return value.strip().strip("'\"")

def mostly_binary(text: str) -> bool:
    if not text: return True
    return (sum(1 for ch in text if ch not in PRINTABLE and ch not in "\n\r\t") / len(text)) > 0.15

def bytes_to_text(raw: bytes) -> str | None:
    for encoding in ("utf-8", "latin-1"):
        try: text = raw.decode(encoding)
        except UnicodeDecodeError: continue
        if not text: continue
        if not mostly_binary(text) or thai_char_ratio(text) >= THAI_CHAR_MIN_RATIO: return text
    return None

def is_effectively_binary(text: str) -> bool: return mostly_binary(text) and thai_char_ratio(text) < THAI_CHAR_MIN_RATIO
def has_control_chars(text: str) -> bool:
    if not text: return True
    return (sum(1 for ch in text if not ch.isprintable() and ch not in "\n\r\t") / len(text)) > 0.15

RESIDUAL_ARTIFACT_RE = re.compile(r"&#|&[a-zA-Z][a-zA-Z0-9]*;|%[0-9A-Fa-f]{2}|\\x[0-9A-Fa-f]{2}|\\[0-7]{1,3}")
def has_residual_encoding_artifact(text: str) -> bool: return bool(RESIDUAL_ARTIFACT_RE.search(text))
def looks_like_rotatable_text(text: str) -> bool: return len(text) >= 3 and any(ch.isalpha() for ch in text)

def rot_n(text: str, shift: int) -> str:
    out = []
    for ch in text:
        if 'a' <= ch <= 'z': out.append(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z': out.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
        else: out.append(ch)
    return "".join(out)

def rot5(text: str) -> str:
    return "".join(chr((ord(ch)-ord('0')+5)%10+ord('0')) if '0'<=ch<='9' else ch for ch in text)
def rot13(text: str) -> str: return rot_n(text, 13)
def rot18(text: str) -> str:
    return "".join(chr((ord(ch)-ord('0')+5)%10+ord('0')) if '0'<=ch<='9' else (rot_n(ch,13) if ch.isalpha() else ch) for ch in text)
def rot47(text: str) -> str:
    return "".join(chr(33+(ord(ch)+47-33)%94) if 33<=ord(ch)<=126 else ch for ch in text)

def atbash(text: str) -> str:
    return "".join(chr(ord('z')-(ord(ch)-ord('a'))) if 'a'<=ch<='z' else chr(ord('Z')-(ord(ch)-ord('A'))) if 'A'<=ch<='Z' else ch for ch in text)

THAI_CONSONANTS = "กขฃคฅฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรลวศษสหฬอฮ"
THAI_ROT_MIN_CONSONANTS = 3

def thai_rot_n(text: str, shift: int) -> str:
    n = len(THAI_CONSONANTS)
    return "".join(THAI_CONSONANTS[(THAI_CONSONANTS.find(ch)+shift)%n] if THAI_CONSONANTS.find(ch)>=0 else ch for ch in text)

def looks_like_thai_rotatable_text(text: str) -> bool:
    return len(text) >= 3 and sum(1 for ch in text if ch in THAI_CONSONANTS) >= THAI_ROT_MIN_CONSONANTS

THAI_POLYBIUS_CONSONANTS = THAI_CONSONANTS[:25]

def _build_thai_polybius() -> tuple[dict[str, str], dict[str, str]]:
    enc, dec = {}, {}
    for i, ch in enumerate(THAI_POLYBIUS_CONSONANTS):
        row, col = divmod(i, 5); code = f"{row+1}{col+1}"
        enc[ch] = code; dec[code] = ch
    return enc, dec

_THAI_POLYBIUS_ENC, _THAI_POLYBIUS_DEC = _build_thai_polybius()

def is_substitution_scheme(name: str) -> bool:
    return name.startswith("rot") or name.startswith("thairot") or name in {"atbash","thai_atbash","xor_singlebyte"}
def is_always_succeeds_scheme(name: str) -> bool:
    return is_substitution_scheme(name) or name in {"reverse","thai_polybius"}

VALIDATED_DECODE_BONUS = 8.0
WEAK_VALIDATION_SCHEMES = {"base36","base58","base62","reverse","thai_polybius"}
ONCE_PER_CHAIN_SCHEMES  = {"quoted_printable","url","malbolge","brainfuck","thai_polybius"}
DENSE_LOW_CONFIDENCE_SCHEMES = {"base2","base16","base32","ascii85","base85","z85","base91","base92","xor_singlebyte"}
MIN_LENGTH_FOR_DENSE_BONUS = 18
SUBSTITUTION_LEGIBILITY_BONUS, SUBSTITUTION_LEGIBILITY_THAI_THRESHOLD = 4.0, 3.0
THAI_ROT_MIN_WORD_HITS = 3
WEAK_CHAIN_CAP_SCHEMES = {"base36","base58","base62"}
MAX_WEAK_CHAIN_LENGTH = 3

def thai_rot_word_evidence(text: str) -> bool:
    return sum(1 for w in THAI_COMMON_WORDS if w in text) >= THAI_ROT_MIN_WORD_HITS

def substitution_legibility_bonus(scheme: str, decoded: str) -> float:
    if not (scheme.startswith("rot") or scheme.startswith("thairot") or scheme in {"atbash","reverse","thai_atbash"}): return 0.0
    if scheme in {"rot5","rot18"} and any(ch.isdigit() for ch in decoded): return 0.0
    tokens = _dictionary_tokens(decoded)
    if tokens and sum(1 for t in tokens if t in COMMON_ENGLISH_WORDS or t in CTF_MARKER_WORDS) / len(tokens) >= 0.5:
        return SUBSTITUTION_LEGIBILITY_BONUS
    if dictionary_confidence_bonus(decoded) >= DICTIONARY_MAX_BONUS: return SUBSTITUTION_LEGIBILITY_BONUS
    if scheme.startswith("thairot") or scheme in {"reverse","atbash","thai_atbash"}:
        return SUBSTITUTION_LEGIBILITY_BONUS if thai_rot_word_evidence(decoded) else 0.0
    return SUBSTITUTION_LEGIBILITY_BONUS if thai_confidence_bonus(decoded) >= SUBSTITUTION_LEGIBILITY_THAI_THRESHOLD else 0.0

URL_LEGIBILITY_BONUS, URL_LEGIBILITY_THAI_THRESHOLD = 3.0, 3.0
def url_legibility_bonus(scheme: str, decoded: str) -> float:
    if scheme != "url": return 0.0
    return URL_LEGIBILITY_BONUS if (dictionary_confidence_bonus(decoded)>=DICTIONARY_MAX_BONUS or thai_confidence_bonus(decoded)>=URL_LEGIBILITY_THAI_THRESHOLD) else 0.0

UNICODE_LEGIBILITY_BONUS = 3.0
def unicode_legibility_bonus(scheme: str, decoded: str) -> float:
    if scheme != "punycode" or is_effectively_binary(decoded): return 0.0
    return UNICODE_LEGIBILITY_BONUS if sum(1 for ch in decoded if ord(ch)>127 and ch.isalpha())>=1 else 0.0

def gets_validated_bonus(scheme: str) -> bool:
    if scheme in {"xor_singlebyte","xor_multikey"}: return True
    return not is_substitution_scheme(scheme) and scheme not in WEAK_VALIDATION_SCHEMES

def trailing_substitution_run(chain: tuple[str, ...]) -> int:
    count = 0
    for scheme in reversed(chain):
        if is_always_succeeds_scheme(scheme): count += 1
        else: break
    return count

def total_substitution_count(chain: tuple[str, ...]) -> int:
    return sum(1 for s in chain if is_always_succeeds_scheme(s))
def total_weak_chain_count(chain: tuple[str, ...]) -> int:
    return sum(1 for s in chain if s in WEAK_CHAIN_CAP_SCHEMES)

def has_boundaried_token(text: str, word: str) -> bool:
    for match in re.finditer(re.escape(word), text, re.IGNORECASE):
        token = match.group(); start, end = match.start(), match.end()
        if token.isupper():
            if start == 0 or not text[start-1].isalnum() or text[start-1].islower(): return True
            continue
        if (start == 0 or not text[start-1].isalnum()) and (end == len(text) or not text[end].isalnum()): return True
    return False

FULL_FLAG_PATTERN = re.compile(r"\b[A-Za-z0-9_]{2,20}\{[^{}]{1,200}\}")

def has_full_flag_pattern(text: str) -> bool:
    match = FULL_FLAG_PATTERN.search(text)
    if not match: return False
    tag = match.group().split("{", 1)[0].lower()
    return "flag" in tag or "ctf" in tag or "picoctf" in tag or "htb" in tag

FLAG_CONTEXT_MIN_REMAINDER_FOR_CHECK, FLAG_CONTEXT_MIN_TOKEN_RATIO, FLAG_CONTEXT_MIN_WORD_LEN = 4, 0.35, 3

def _flag_context_word_tokens(remainder: str) -> list[str]:
    return [s.lower() for c in remainder.split() if (s := c.strip("'\".,;:!?()[]{}")) and s.isalpha()]

def flag_context_is_plausible(text: str) -> bool:
    match = FULL_FLAG_PATTERN.search(text)
    if not match: return False
    remainder = text[:match.start()] + text[match.end():]
    if len(remainder) < FLAG_CONTEXT_MIN_REMAINDER_FOR_CHECK: return True
    words = _flag_context_word_tokens(remainder)
    if any(len(w) >= FLAG_CONTEXT_MIN_WORD_LEN and w in COMMON_ENGLISH_WORDS for w in words): return True
    all_tokens = remainder.split(); n = len(all_tokens)
    if n == 0: return True
    if n >= 3: return (len(words) / n) >= FLAG_CONTEXT_MIN_TOKEN_RATIO
    return len(words) == n

def shannon_entropy(text: str) -> float:
    if not text: return 0.0
    return -sum((c/len(text))*math.log2(c/len(text)) for c in {ch: text.count(ch) for ch in set(text)}.values())

AES_DETECTION_BLOCK_SIZE, AES_DETECTION_MIN_BYTES, AES_DETECTION_ENTROPY_RATIO_THRESHOLD = 16, 48, 0.90

def shannon_entropy_bytes(data: bytes) -> float:
    if not data: return 0.0
    n = len(data); return -sum((c/n)*math.log2(c/n) for c in Counter(data).values())

def normalized_entropy_ratio(data: bytes) -> float:
    n = len(data)
    if n < 2: return 0.0
    max_possible = math.log2(min(256, n))
    return (shannon_entropy_bytes(data) / max_possible) if max_possible > 0 else 0.0

def _try_parse_as_bytes_for_detection(value: str) -> bytes | None:
    compact = re.sub(r"\s+", "", value)
    if re.fullmatch(r"[0-9A-Fa-f]+", compact) and len(compact) % 2 == 0 and compact:
        try: return bytes.fromhex(compact)
        except ValueError: pass
    if re.fullmatch(r"[A-Za-z0-9+/]+=*", compact) and len(compact) >= 4:
        try: return base64.b64decode(value + ("=" * ((4 - len(value) % 4) % 4)), validate=True)
        except (binascii.Error, ValueError): pass
    try: return value.encode("latin-1")
    except UnicodeEncodeError: return None

def detect_likely_block_cipher(value: str) -> str | None:
    if dictionary_confidence_bonus(value) >= DICTIONARY_MAX_BONUS or thai_confidence_bonus(value) >= SUBSTITUTION_LEGIBILITY_THAI_THRESHOLD: return None
    raw = _try_parse_as_bytes_for_detection(value)
    if raw is None or len(raw) < AES_DETECTION_MIN_BYTES or len(raw) % AES_DETECTION_BLOCK_SIZE != 0: return None
    ratio = normalized_entropy_ratio(raw)
    if ratio < AES_DETECTION_ENTROPY_RATIO_THRESHOLD: return None
    entropy = shannon_entropy_bytes(raw)
    return (f"หมายเหตุ: ข้อมูลนี้มีลักษณะคล้ายถูกเข้ารหัสด้วย block cipher (เช่น AES) — ยาว {len(raw)} bytes "
            f"(หาร {AES_DETECTION_BLOCK_SIZE} ลงตัว), entropy {entropy:.2f} bits/byte ({ratio*100:.0f}% ของค่าสูงสุดที่เป็นไปได้) "
            f"ซึ่งเป็นลักษณะเฉพาะของ ciphertext ที่เข้ารหัสแล้ว ไม่ใช่ encoding ทั่วไป "
            f"ต้องมี key ที่ถูกต้องถึงจะถอดได้ — เครื่องมือนี้ auto-decode ต่อไม่ได้")

def printable_ratio_unicode_aware(text: str) -> float:
    if not text: return 0.0
    return sum(1 for ch in text if ch in PRINTABLE or ch.isprintable() or ch in "\n\r\t") / len(text)

def _score_parts(text: str) -> tuple:
    pr = printable_ratio_unicode_aware(text)
    ar = sum(1 for ch in text if ch.isalnum() or ch in " _-{}[]():;,.!?/@#$%^&*+=\n\r\t") / len(text)
    lower = text.lower()
    wb = sum(2.0 for w in COMMON_WORDS if w in lower)
    fb = 10.0 if re.search(r"(flag|ctf)[\{_\-:]", lower) else (3.0 if has_boundaried_token(text,"ctf") or has_boundaried_token(text,"flag") else 0.0)
    ent = shannon_entropy(text); ep = abs(ent - 4.2) * 0.5
    has_d = any(c.isdigit() for c in text); has_a = any(c.isalpha() for c in text)
    cs = (2.5 if "_" in text else 2.0) if (has_d and has_a and ("_" in text or "{" in text or "}" in text or "-" in text)) else 0.0
    lb = (min(len(text), 80) / 80) if not (" " not in text and len(text) > 20 and wb == 0 and cs == 0) else -3.0
    chi2 = english_chi_squared(text)
    cp = min(chi2 / 140.0, 6.0) if chi2 is not None else (1.5 if len(text) >= 5 else 0.0)
    db, tb = dictionary_confidence_bonus(text), thai_confidence_bonus(text)
    return pr, ar, wb, fb, ep, cs, lb, cp, db, tb

def score_text(text: str) -> float:
    if not text: return -999.0
    pr, ar, wb, fb, ep, cs, lb, cp, db, tb = _score_parts(text)
    return pr*8 + ar*5 + wb + fb + cs + lb - ep - cp + db + tb

def _score_breakdown(text: str) -> dict:
    if not text: return {"total": -999.0}
    pr, ar, wb, fb, ep, cs, lb, cp, db, tb = _score_parts(text)
    total = pr*8 + ar*5 + wb + fb + cs + lb - ep - cp + db + tb
    return {
        "printable_ratio_contrib": round(pr*8, 4), "alpha_space_ratio_contrib": round(ar*5, 4),
        "word_bonus": round(wb, 4), "flag_bonus": round(fb, 4), "ctf_style_bonus": round(cs, 4),
        "length_bonus": round(lb, 4), "entropy_penalty": round(-ep, 4), "chi2_penalty": round(-cp, 4),
        "dict_bonus": round(db, 4), "thai_bonus": round(tb, 4), "total": round(total, 4)
    }

def safe_preview(text: str, limit: int = 120) -> str:
    preview = text.encode("unicode_escape", errors="backslashreplace").decode("ascii")
    return (preview[:limit-3] + "...") if len(preview) > limit else preview
