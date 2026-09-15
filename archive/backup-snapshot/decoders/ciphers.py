from __future__ import annotations
import re
from core.registry import register_decoder
from core.heuristics import (
    _log_debug, bytes_to_text, is_effectively_binary, looks_like_rotatable_text,
    rot_n, rot5, rot18, rot47, atbash, THAI_CONSONANTS, THAI_ROT_MIN_CONSONANTS,
    thai_rot_n, looks_like_thai_rotatable_text, _THAI_POLYBIUS_DEC
)

@register_decoder(name="reverse", category="cipher")
def decode_reverse(value: str) -> str | None:
    compact = value.strip()
    if len(compact) < 4 or is_effectively_binary(compact): return None
    rev = compact[::-1]; return rev if rev != compact else None

MORSE_TABLE = {
    ".-":"A","-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F","--.":"G","....":"H","..":"I",".---":"J",
    "-.-":"K",".-..":"L","--":"M","-.":"N","---":"O",".--.":"P","--.-":"Q",".-.":"R","...":"S","-":"T",
    "..-":"U","...-":"V",".--":"W","-..-":"X","-.--":"Y","--..":"Z",
    "-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",".....":"5","-....":"6","--...":"7","---..":"8","----.":"9"
}

@register_decoder(name="morse", category="cipher")
def decode_morse(value: str) -> str | None:
    compact = value.strip()
    if not compact or not re.fullmatch(r"[.\-\s/|_]+", compact): return None
    words = re.split(r"\s*[/|]\s*|_+|\s{2,}", compact); out_words = []
    for word in words:
        letters = [MORSE_TABLE.get(tok) for tok in word.split()]
        if not letters or any(l is None for l in letters): return None
        out_words.append("".join(letters))
    res = " ".join(out_words).strip(); return res or None

NATO_PHONETIC_TABLE = {
    "alpha":"A","bravo":"B","charlie":"C","delta":"D","echo":"E","foxtrot":"F","golf":"G","hotel":"H",
    "india":"I","juliett":"J","juliet":"J","kilo":"K","lima":"L","mike":"M","november":"N","oscar":"O",
    "papa":"P","quebec":"Q","romeo":"R","sierra":"S","tango":"T","uniform":"U","victor":"V","whiskey":"W",
    "xray":"X","x-ray":"X","yankee":"Y","zulu":"Z","zero":"0","one":"1","two":"2","three":"3","four":"4",
    "five":"5","six":"6","seven":"7","eight":"8","nine":"9","niner":"9","fower":"4","tree":"3","fife":"5"
}

@register_decoder(name="nato_phonetic", category="cipher")
def decode_nato_phonetic(value: str) -> str | None:
    tokens = value.strip().split()
    if len(tokens) < 2: return None
    letters = [NATO_PHONETIC_TABLE.get(tok.lower().strip(",.;:")) for tok in tokens]
    if any(l is None for l in letters): return None
    res = "".join(letters); return res if res and res != value else None

@register_decoder(name="brainfuck", category="cipher")
def decode_brainfuck(value: str) -> str | None:
    code = "".join(ch for ch in value if not ch.isspace())
    if len(code) < 8 or any(ch not in "+-<>.,[]" for ch in code) or "." not in code or code.count("[") != code.count("]"): return None
    bracket_pairs: dict[int,int] = {}; stack: list[int] = []
    for i, ch in enumerate(code):
        if ch == "[": stack.append(i)
        elif ch == "]":
            if not stack: return None
            s = stack.pop(); bracket_pairs[s] = i; bracket_pairs[i] = s
    if stack: return None
    tape, pointer, ip, output, steps = bytearray(30000), 0, 0, bytearray(), 0
    while ip < len(code):
        steps += 1
        if steps > 200000: return None
        ch = code[ip]
        if ch == "+": tape[pointer] = (tape[pointer] + 1) % 256
        elif ch == "-": tape[pointer] = (tape[pointer] - 1) % 256
        elif ch == ">":
            pointer += 1
            if pointer >= 30000: return None
        elif ch == "<":
            pointer -= 1
            if pointer < 0: return None
        elif ch == ".": output.append(tape[pointer])
        elif ch == ",": tape[pointer] = 0
        elif ch == "[":
            if tape[pointer] == 0: ip = bracket_pairs[ip]
        elif ch == "]":
            if tape[pointer] != 0: ip = bracket_pairs[ip]
        ip += 1
    decoded = bytes_to_text(bytes(output)); return decoded if decoded and decoded != value else None

MALBOLGE_MEM_SIZE, MALBOLGE_MIN_SOURCE_LEN = 59049, 8
_MALBOLGE_VALID_OPS = frozenset({4, 5, 23, 39, 40, 62, 68, 81})
_MALBOLGE_REAL_OPS  = frozenset({4, 5, 23, 39, 40, 62, 81})
_MALBOLGE_XLAT_IN  = """!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"""
_MALBOLGE_XLAT_OUT = """5z]&gqtyfr$(we4{WP)H-Zn,[%\\3dL+Q;>U!pJS72FhOA1CB6v^=I_0/8|jsb9m<.TVac`uY*MK'X~xDl}REokN:#?G"i@"""
_MALBOLGE_XLAT = str.maketrans(_MALBOLGE_XLAT_IN, _MALBOLGE_XLAT_OUT)

def _malbolge_crazy(a: int, d: int) -> int:
    table = [[1,0,0],[1,0,2],[2,2,1]]; res, base = 0, 1
    for _ in range(10): res += table[d%3][a%3]*base; a //= 3; d //= 3; base *= 3
    return res

def _malbolge_rot_right(v: int) -> int: return (v // 3) + (v % 3) * (MALBOLGE_MEM_SIZE // 3)

def _looks_like_malbolge(code: str) -> bool:
    pos = 0
    for ch in code:
        if ch in ' \t\r\n': continue
        val = ord(ch)
        if not (33 <= val <= 126) or (val + pos) % 94 not in _MALBOLGE_VALID_OPS: return False
        pos += 1
    return pos >= MALBOLGE_MIN_SOURCE_LEN

@register_decoder(name="malbolge", category="cipher")
def decode_malbolge(value: str) -> str | None:
    code = "".join(ch for ch in value if ch in ' \t\r\n' or 33 <= ord(ch) <= 126)
    op_chars = [ch for ch in code if ch not in ' \t\r\n' and 33 <= ord(ch) <= 126]
    if len(op_chars) < MALBOLGE_MIN_SOURCE_LEN or not _looks_like_malbolge(code): return None
    if (sum(1 for i,ch in enumerate(op_chars) if (ord(ch)+i)%94 in _MALBOLGE_REAL_OPS) < max(2, len(op_chars)//16)
            or sum(1 for i,ch in enumerate(op_chars) if (ord(ch)+i)%94 == 5) < 1): return None
    mem, ptr = [0] * MALBOLGE_MEM_SIZE, 0
    for ch in code:
        if ch in ' \t\r\n' or not (33 <= ord(ch) <= 126): continue
        mem[ptr] = ord(ch); ptr += 1
        if ptr >= MALBOLGE_MEM_SIZE: break
    for i in range(ptr, MALBOLGE_MEM_SIZE): mem[i] = _malbolge_crazy(mem[i-1], mem[i-2])
    c_reg, d_reg, a_reg, output_chars, steps = 0, 0, 0, [], 0
    try:
        while steps < 2000000:
            steps += 1; cell = mem[c_reg]
            if not (33 <= cell <= 126): break
            opcode = (cell + c_reg) % 94
            if   opcode == 4:  c_reg = mem[d_reg]
            elif opcode == 5:
                output_chars.append(chr(a_reg % 256))
                if len(output_chars) > 4096: break
            elif opcode in (23, 81): break
            elif opcode == 39: v = _malbolge_rot_right(mem[d_reg]); mem[d_reg] = v; a_reg = v
            elif opcode == 40: d_reg = mem[d_reg]
            elif opcode == 62: v = _malbolge_crazy(a_reg, mem[d_reg]); mem[d_reg] = v; a_reg = v
            if 33 <= mem[c_reg] <= 126: mem[c_reg] = ord(chr(mem[c_reg]).translate(_MALBOLGE_XLAT))
            c_reg = 0 if c_reg == MALBOLGE_MEM_SIZE - 1 else c_reg + 1
            d_reg = 0 if d_reg == MALBOLGE_MEM_SIZE - 1 else d_reg + 1
    except Exception as e: _log_debug(f"decode_malbolge: VM error: {e!r}"); return None
    if len(output_chars) < 4: return None
    decoded = bytes_to_text("".join(output_chars).encode("latin-1", errors="replace"))
    return decoded if decoded and decoded != value else None

BACON_TABLE = {
    "AAAAA":"A","AAAAB":"B","AAABA":"C","AAABB":"D","AABAA":"E","AABAB":"F","AABBA":"G","AABBB":"H",
    "ABAAA":"I","ABAAB":"J","ABABA":"K","ABABB":"L","ABBAA":"M","ABBAB":"N","ABBBA":"O","ABBBB":"P",
    "BAAAA":"Q","BAAAB":"R","BAABA":"S","BAABB":"T","BABAA":"U","BABAB":"V","BABBA":"W","BABBB":"X",
    "BBAAA":"Y","BBAAB":"Z"
}
BACON_TABLE_24 = dict(BACON_TABLE); BACON_TABLE_24["ABAAB"] = "I"; BACON_TABLE_24["BABAB"] = "U"

@register_decoder(name="bacon", category="cipher")
def decode_bacon(value: str) -> str | None:
    compact = re.sub(r"[\s/_,.\-]+", "", value).upper()
    if len(compact) < 15 or len(compact) % 5 != 0 or not re.fullmatch(r"[AB]+", compact): return None
    letters = [BACON_TABLE.get(compact[i:i+5]) or BACON_TABLE_24.get(compact[i:i+5]) for i in range(0, len(compact), 5)]
    if any(l is None for l in letters): return None
    res = "".join(letters); return res if res and res != compact else None

@register_decoder(name="rot5", category="cipher")
def decode_rot5(v: str) -> str | None:
    if len(re.findall(r"\d", v)) < 3: return None
    c = rot5(v); return c if c != v else None

@register_decoder(name="rot18", category="cipher")
def decode_rot18(v: str) -> str | None:
    if not (re.search(r"\d", v) and looks_like_rotatable_text(v)): return None
    c = rot18(v); return c if c != v else None

@register_decoder(name="rot47", category="cipher")
def decode_rot47(v: str) -> str | None:
    if not looks_like_rotatable_text(v): return None
    c = rot47(v); return c if c != v else None

@register_decoder(name="atbash", category="cipher")
def decode_atbash(v: str) -> str | None:
    if not looks_like_rotatable_text(v): return None
    c = atbash(v); return c if c != v else None

@register_decoder(name="rot_all", category="cipher")
def decode_rot_all(value: str) -> list[tuple[str, str]]:
    if not looks_like_rotatable_text(value): return []
    return [(f"rot{(26-shift)%26}", cand) for shift in range(1, 26) if (cand := rot_n(value, shift)) != value]

@register_decoder(name="thai_rot_all", category="cipher")
def decode_thai_rot_all(value: str) -> list[tuple[str, str]]:
    if not looks_like_thai_rotatable_text(value): return []
    n = len(THAI_CONSONANTS)
    return [(f"thairot{(n-shift)%n}", cand) for shift in range(1, n) if (cand := thai_rot_n(value, shift)) != value]

@register_decoder(name="thai_atbash", category="cipher")
def decode_thai_atbash(value: str) -> str | None:
    if sum(1 for ch in value if ch in THAI_CONSONANTS) < THAI_ROT_MIN_CONSONANTS: return None
    n = len(THAI_CONSONANTS)
    res = "".join(THAI_CONSONANTS[n-1-idx] if (idx:=THAI_CONSONANTS.find(ch))>=0 else ch for ch in value)
    return res if res != value else None

@register_decoder(name="thai_polybius", category="cipher")
def decode_thai_polybius(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if not re.fullmatch(r"[1-5]+", compact) or len(compact) % 2 != 0 or len(compact) < 4: return None
    pairs = [compact[i:i+2] for i in range(0, len(compact), 2)]
    if not all(p in _THAI_POLYBIUS_DEC for p in pairs): return None
    res = "".join(_THAI_POLYBIUS_DEC[p] for p in pairs); return res if res and res != value else None
