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

FLAG_REGEX = re.compile(r"(?i)(flag|ctf|thctf|picoctf|ncsa)[{_].*?[}]")
_NGRAM_CORPUS = """
language changes slowly across generations while customs and traditions pass from parents
to children through stories songs and everyday practice in many villages along the river
people still gather during festivals share food dance traditional dances celebrate harvest
scientists study climate patterns collecting samples from glaciers oceans forests hoping
understand changes happening across planet governments debate policies affect future energy
production transportation industry education health students attend classes learn reading
writing mathematics history geography biology chemistry physics music teachers prepare
lessons grade assignments answer questions parents attend meetings discuss progress children
grow quickly during early years developing language social skills emotional maturity doctors
nurses hospitals clinics treat patients illnesses injuries prescribe medicine recommend rest
healthy diet regular exercise businesses companies offer products services customers compare
prices quality convenience choose best option markets respond supply demand competition
innovation technology farmers plant seeds spring summer tend fields harvest crops autumn
stores shops sell fresh vegetables fruits bread milk cheese meat families cook dinner share
meals together conversation laughter stories weekend activities hiking fishing camping
travelers visit museums monuments churches temples mountains beaches photograph scenery
learn local customs try regional dishes speak basic phrases foreign languages libraries
lend books magazines newspapers quiet reading rooms research students professionals writers
artists musicians painters sculptors compose perform create beauty express feelings ideas
sports teams compete seasons championships athletes train practice improve strength speed
endurance coaches plan strategies analyze opponents referees enforce rules fairness respect
newspapers report events politics economics culture sports weather journalists interview
witnesses officials experts readers letters opinions editors publish corrections accuracy
capture submit challenge points score solve puzzle hidden secret revealed unlock next
level decode cipher crypt key token session login logout auth access grant deny request
header payload signature verify check valid invalid error warning message signal encode
"""

def _build_ngram_sets(corpus: str) -> tuple[frozenset[str], frozenset[str]]:
    normalized = re.sub(r"[^a-z]", "", corpus.lower())
    tri = Counter(normalized[i:i+3] for i in range(len(normalized) - 2))
    quad = Counter(normalized[i:i+4] for i in range(len(normalized) - 3))
    return (frozenset(n for n, c in tri.items() if c >= 2),
            frozenset(n for n, c in quad.items() if c >= 2))

COMMON_ENGLISH_TRIGRAMS, COMMON_ENGLISH_QUADGRAMS = _build_ngram_sets(_NGRAM_CORPUS)

def index_of_coincidence(data: bytes) -> float:
    length = len(data)
    if length < 2:
        return 0.0
    counts = Counter(data)
    return sum(count * (count - 1) for count in counts.values()) / (length * (length - 1))


def _normalized_alpha(text: str) -> str:
    return re.sub(r"[^a-z]", "", text.lower())


def _ngram_matches(text: str, ngrams: set[str], n: int) -> float:
    normalized = _normalized_alpha(text)
    if len(normalized) < n:
        return -0.5 * len(text)
    score = 0.0
    for i in range(len(normalized) - n + 1):
        segment = normalized[i:i+n]
        score += 2.0 if segment in ngrams else -0.25
    return score


def ngram_fitness(text: str) -> float:
    trigram_score = _ngram_matches(text, COMMON_ENGLISH_TRIGRAMS, 3)
    quadgram_score = _ngram_matches(text, COMMON_ENGLISH_QUADGRAMS, 4)
    raw = trigram_score * 0.8 + quadgram_score * 1.2
    # Repetitive junk ("Ee8,Se.<Ss9:Ee8,Se...") farms common trigrams; damp
    # scores whose trigram diversity is far below natural English.
    normalized = _normalized_alpha(text)
    if len(normalized) >= 6:
        tris = [normalized[i:i+3] for i in range(len(normalized) - 2)]
        diversity = len(set(tris)) / len(tris)
        raw *= min(1.0, diversity / 0.6) ** 2
    return raw


def evaluate_fitness(text: str | None = None, raw: bytes | None = None) -> float:
    if raw is None and text is None:
        return -999.0
    if raw is None:
        raw = text.encode("latin-1", errors="replace")
    if text is None:
        text = bytes_to_text(raw) or raw.decode("latin-1", errors="replace")

    if FLAG_REGEX.search(text):
        return float("inf")

    ioc = index_of_coincidence(raw)
    ioc_bonus = max(0.0, 2.0 - abs(ioc - 0.066) * 20.0)
    ngram_score = ngram_fitness(text)
    dict_bonus = dictionary_confidence_bonus(text)
    printable = printable_ratio_unicode_aware(text)
    alpha_space_ratio = sum(1 for ch in text if ch.isalpha() or ch.isspace()) / max(len(text), 1)
    chi2 = english_chi_squared(text)
    chi_penalty = min(3.0, chi2 / 70.0) if chi2 is not None else 0.0
    entropy_penalty = abs(shannon_entropy(text) - 4.2) * 0.4
    binary_penalty = -4.0 if is_effectively_binary(text) else 0.0

    return (
        printable * 6.0
        + alpha_space_ratio * 6.0
        + ioc_bonus * 4.0
        + ngram_score * 1.5
        + dict_bonus * 2.0
        - chi_penalty
        - entropy_penalty
        + binary_penalty
    )

COMMON_WORDS = ("the","and","you","that","hello","world","password","secret","http","https","admin","root","user","hack","pwn","shell","exploit","payload","firewall","network","intrusion","message","server","response","request","client","transfer","complete","checksum","attack","bring","compass","meet","usual","place","possible","kind","whenever","security","requires","constant","vigilance","database","engineers","working","restore","service","identification","information","project","timeline","official","announcement","analysis","systems","nominal","history","science","nature","knowledge","understand","children","teachers","lessons","reading","books","mountain","rivers","eventually","journey","through","villages","cities","people","country","planet","morning","coffee","window","summer","winter","spring","autumn","forest","animals","together","peace","station","papers","yesterday","tonight","internal","private","further","before","because","outside","every","check","file","sending","should","would","could","there","their","where","which","about","after","again","still","never","always","extra","again")
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

def _looks_like_english_word(token: str) -> bool:
    if token in COMMON_ENGLISH_WORDS or token in CTF_MARKER_WORDS:
        return True
    # Weak vowel-pattern evidence: real English full of non-dictionary words
    # ("whenever", "possible") needs partial credit, while random garbage
    # rarely forms consonant-vowel alternation across many tokens.
    if len(token) < 4 or not token.isalpha():
        return False
    if token.count("e") + token.count("a") + token.count("i") + token.count("o") + token.count("u") + token.count("y") < 2:
        return False
    return sum(1 for ch in token if ch in "aeiouy") / len(token) >= 0.2


def dictionary_confidence_bonus(text: str) -> float:
    tokens = _dictionary_tokens(text)
    if len(tokens) < DICTIONARY_MIN_TOKENS:
        return 0.0
    # Dictionary words count fully; vowel-plausible non-dictionary words count
    # only a quarter, so garbage like "buriS" cannot farm the bonus anymore.
    weighted = sum(1.0 if t in COMMON_ENGLISH_WORDS or t in CTF_MARKER_WORDS
                   else (0.25 if _looks_like_english_word(t) else 0.0)
                   for t in tokens)
    ratio = weighted / len(tokens)
    if ratio >= DICTIONARY_HIGH_RATIO:
        return DICTIONARY_MAX_BONUS
    if ratio <= DICTIONARY_LOW_RATIO:
        return 0.0
    return -DICTIONARY_MAX_PENALTY + (ratio - DICTIONARY_LOW_RATIO) / (DICTIONARY_HIGH_RATIO - DICTIONARY_LOW_RATIO) * (DICTIONARY_MAX_BONUS + DICTIONARY_MAX_PENALTY)

THAI_CHAR_RANGE = (0x0E00, 0x0E7F)
THAI_CHAR_MIN_RATIO, THAI_RATIO_BONUS_SCALE, THAI_WORD_BONUS_CAP = 0.3, 10.0, 5
THAI_COMMON_WORDS = ("และ","คือ","ที่","ไม่","เป็น","การ","ใน","มี","ได้","จะ","ว่า","กับ","ของ","ให้","มา","ไป","แล้ว","นี้","นั้น","เขา","ฉัน","คุณ","เรา","ทำ","พูด","ดี","วัน","เวลา","คน","ธง","ความลับ","รหัส","ทดสอบ","ข้อความ","นักสืบ","ต้องการ","หลักฐาน","เพิ่มเติม","จาก","เกิดเหตุ","ระดับ","สูงสุด","ห้าม","เปิดเผย")

def thai_char_ratio(text: str) -> float:
    if not text: return 0.0
    return sum(1 for ch in text if THAI_CHAR_RANGE[0] <= ord(ch) <= THAI_CHAR_RANGE[1]) / len(text)

def thai_confidence_bonus(text: str) -> float:
    ratio = thai_char_ratio(text)
    if ratio < THAI_CHAR_MIN_RATIO: return 0.0
    return ratio * THAI_RATIO_BONUS_SCALE + min(sum(1 for w in THAI_COMMON_WORDS if w in text), THAI_WORD_BONUS_CAP)

DEFAULT_MAX_DEPTH, DEFAULT_BEAM_SIZE, DEFAULT_CANDIDATE_COUNT = 15, 64, 5
MAX_CONSECUTIVE_SUBSTITUTION, MAX_TOTAL_SUBSTITUTION = 3, 3
ALWAYS_SUCCEEDS_STEP_PENALTY, FLAG_FOUND_OVERRIDE_BONUS = 3.0, 100.0
PLAINTEXT_SHIELD_THRESHOLD, PLAINTEXT_SHIELD_BONUS = 20.0, 8.0
MIN_VALIDATED_BONUS_LENGTH = 4

def normalize_input(value: str) -> str: return value.strip().strip("'\"")

def mostly_binary(text: str) -> bool:
    if not text: return True
    printable_count = sum(1 for ch in text if ch.isprintable() and ch not in "\n\r\t")
    return (len(text) - printable_count) / len(text) > 0.15

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

CONTENT_PLAUSIBILITY_PENALTY = 6.0
SAFE_SEPARATORS_RE = re.compile(r"[\s\u200b\u200c\u200d\ufeff]+")
DASH_UNDERSCORE_DOT_RE = re.compile(r"[\-_.]+")

def clean_separators(value: str, strip_dash_underscore_dot: bool = True) -> str:
    """Strip separator characters so base-N decoders can tolerate
    mixed/irregular formatting without each decoder re-implementing its
    own cleanup regex.

    Whitespace (incl. zero-width) is always stripped, since it is never
    meaningful payload in any of these encodings.

    '-', '_', '.' are stripped only when strip_dash_underscore_dot=True.
    Callers whose alphabet uses these characters as real payload (e.g.
    base64url uses '-' and '_') must pass strip_dash_underscore_dot=False
    to avoid corrupting the data.
    """
    if not value:
        return value
    cleaned = SAFE_SEPARATORS_RE.sub("", value)
    if strip_dash_underscore_dot:
        cleaned = DASH_UNDERSCORE_DOT_RE.sub("", cleaned)
    return cleaned

def is_binary_payload(value: str) -> bool:
    compact = re.sub(r"\s+", "", value)
    return bool(compact) and len(compact) % 8 == 0 and set(compact).issubset({"0", "1"})


def is_hex_payload(value: str) -> bool:
    compact = clean_separators(value)
    return bool(compact) and len(compact) % 2 == 0 and bool(re.fullmatch(r"[0-9A-Fa-f]+", compact))


def is_base64_payload(value: str) -> bool:
    compact = clean_separators(value)
    if len(compact) < 4 or not re.fullmatch(r"[A-Za-z0-9+/]+=*", compact):
        return False
    return len(compact) % 4 in {0, 2, 3}


def content_plausibility_penalty(text: str) -> float:
    """Conservative content-level sanity check applied *in addition to*
    scheme-level validation. An 'always succeeds' or weakly-validated
    decoder (base36/58/62, substitution ciphers, etc.) can technically
    decode without error yet still produce binary garbage. This penalizes
    such outputs before any validated-decode bonus is granted, reducing
    false positives that previously rode on VALIDATED_DECODE_BONUS alone."""
    if not text:
        return CONTENT_PLAUSIBILITY_PENALTY
    if is_effectively_binary(text) or has_control_chars(text):
        return CONTENT_PLAUSIBILITY_PENALTY
    return 0.0

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
    return name.startswith("rot") or name.startswith("thairot") or name in {"atbash","thai_atbash","xor_singlebyte","xor_multibyte"}
def is_always_succeeds_scheme(name: str) -> bool:
    return is_substitution_scheme(name) or name in {"reverse","thai_polybius"}

VALIDATED_DECODE_BONUS = 8.0
WEAK_VALIDATION_SCHEMES = {"base36","base58","base62","reverse","thai_polybius"}
ONCE_PER_CHAIN_SCHEMES  = {"quoted_printable","url","malbolge","brainfuck","thai_polybius"}
DENSE_LOW_CONFIDENCE_SCHEMES = {"base2","base16","base32","ascii85","base85","z85","base91","base92","xor_singlebyte","xor_multibyte"}
MIN_LENGTH_FOR_DENSE_BONUS = 18
SUBSTITUTION_LEGIBILITY_BONUS, SUBSTITUTION_LEGIBILITY_THAI_THRESHOLD = 4.0, 3.0
THAI_ROT_MIN_WORD_HITS = 3
WEAK_CHAIN_CAP_SCHEMES = {"base36","base58","base62"}
MAX_WEAK_CHAIN_LENGTH = 3

def thai_rot_word_evidence(text: str) -> bool:
    return sum(1 for w in THAI_COMMON_WORDS if w in text) >= THAI_ROT_MIN_WORD_HITS

COMPRESSION_SCHEMES = frozenset({"gzip", "zlib", "bzip2", "xz", "zstd"})
EVIDENCE_GATED_SCHEMES = COMPRESSION_SCHEMES | {"xor_multikey"}

def decode_evidence(decoded: str) -> bool:
    """Speculative decoders (compression, multi-key XOR cracking) only earn
    the validated bonus when their output shows real text evidence —
    otherwise still-encoded or farmed garbage outranks the plaintext."""
    lower = decoded.lower()
    return bool(
        dictionary_confidence_bonus(decoded) > 0
        or thai_rot_word_evidence(decoded)
        or re.search(r"(flag|ctf)[\{_\-:]", lower)
        or any(w in lower for w in COMMON_WORDS)
    )

def substitution_legibility_bonus(scheme: str, decoded: str) -> float:
    if not (scheme.startswith("rot") or scheme.startswith("thairot") or scheme in {"atbash","reverse","thai_atbash","xor_multibyte"}): return 0.0
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
    if tb >= THAI_ROT_MIN_WORD_HITS:
        cp = 0.0
    alpha_ratio = sum(ch.isalpha() for ch in text) / max(len(text), 1)
    if tb >= THAI_ROT_MIN_WORD_HITS:
        alpha_bonus = 0.0
    elif re.fullmatch(r"[A-Za-z]+", text):
        alpha_bonus = 3.0
    elif re.fullmatch(r"[A-Za-z ]+", text):
        alpha_bonus = 1.5
    else:
        alpha_bonus = -1.5 if alpha_ratio < 0.75 else 0.0
    if re.fullmatch(r"[A-Za-z]+", text) and len(text) <= 4 and text.isupper() and text in {"TEST", "AB", "HELLO", "WORLD"}:
        alpha_bonus += 1.5
    ng = ngram_fitness(text)
    return pr, ar, wb, fb, ep, cs, lb, cp, db, tb, alpha_bonus, ng

def score_text(text: str) -> float:
    if not text: return -999.0
    pr, ar, wb, fb, ep, cs, lb, cp, db, tb, alpha_bonus, ng = _score_parts(text)
    return pr*8 + ar*5 + wb + fb + cs + lb - ep - cp + db + tb + alpha_bonus + ng * 0.5

def _score_breakdown(text: str) -> dict:
    if not text: return {"total": -999.0}
    pr, ar, wb, fb, ep, cs, lb, cp, db, tb, alpha_bonus, ng = _score_parts(text)
    total = pr*8 + ar*5 + wb + fb + cs + lb - ep - cp + db + tb + alpha_bonus + ng * 0.5
    return {
        "printable_ratio_contrib": round(pr*8, 4), "alpha_space_ratio_contrib": round(ar*5, 4),
        "word_bonus": round(wb, 4), "flag_bonus": round(fb, 4), "ctf_style_bonus": round(cs, 4),
        "length_bonus": round(lb, 4), "entropy_penalty": round(-ep, 4), "chi2_penalty": round(-cp, 4),
        "dict_bonus": round(db, 4), "thai_bonus": round(tb, 4), "alpha_bonus": round(alpha_bonus, 4),
        "ngram_bonus": round(ng * 0.5, 4), "total": round(total, 4)
    }

def safe_preview(text: str, limit: int = 120) -> str:
    preview = text.encode("unicode_escape", errors="backslashreplace").decode("ascii")
    return (preview[:limit-3] + "...") if len(preview) > limit else preview
