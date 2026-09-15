#!/usr/bin/env python3
"""TEAM-DECODE full-system benchmark.

Generates 1000 randomized decode challenges (easy / normal / hard / extreme
multi-layer chains), runs them through core.engine.auto_decode and reports
top-1 / top-3 accuracy, per-encoder failure hotspots and timings.

Encoders here are exact inverses of the project decoders (alphabets and
tables are imported from the project itself) and every encoder is
self-verified against the system's decode_once() before use.
"""
from __future__ import annotations

import argparse
import base64
import bz2
import gzip
import hashlib
import hmac
import json
import lzma
import random
import re
import sys
import time
import urllib.parse
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import decoders  # noqa: F401 — populates the decoder registry
from core.engine import auto_decode, decode_once
from core.heuristics import (
    THAI_CONSONANTS, THAI_POLYBIUS_CONSONANTS, _THAI_POLYBIUS_ENC,
    ONCE_PER_CHAIN_SCHEMES,
)

SEED = 42

# ---------------------------------------------------------------- plaintexts

FLAGS = [
    "flag{th1s_1s_a_s3cr3t}", "CTF{mult1_l4y3r_ch4ll3ng3}",
    "picoCTF{th4t_is_n0t_my_l4y3r}", "HTB{d3c0d3_th3_w0rld}",
    "THM{h4ckth3pl4n3t}", "flag{B45E64_1S_FUN}", "flag{x0r_1s_e4sy}",
    "flag{c0mpr3ss10n_t1m3}", "flag{m0rs3_c0d3_r0cks}", "flag{jwt_s3cr3t_k3y}",
    "flag{qwertyuiop123456}", "CTF{Thailand_N0_1}", "flag{d33p_ch4in_g4me}",
    "flag{rev3rs3_1t_tw1c3}", "flag{n0_clu3_l3ft_b3h1nd}",
]
ENGLISH = [
    "The quick brown fox jumps over the lazy dog",
    "Attack at dawn, bring the map and the compass",
    "Data decryption complete, all systems nominal",
    "Never gonna give you up, never gonna let you down",
    "The password database was encrypted yesterday",
    "Server response code 200 OK with payload attached",
    "Security through obscurity is not real security",
    "Meet me at the usual place at nine thirty",
    "Transfer complete, checksum verified OK",
    "Be kind whenever possible, it is always possible",
    "The map is not the territory",
    "Coordinates 13.7563 north 100.5018 east",
]
THAI = [
    "สวัสดีครับนี่คือข้อความลับ",
    "ถอดรหัสข้อความนี้ให้ได้ก่อนเวลาหมด",
    "ทีมดีโคดพร้อมทำงานทุกสถานการณ์",
    "รหัสผ่านคือชื่อสัตว์เลี้ยงของฉัน",
    "นักสืบต้องการหลักฐานเพิ่มเติมจากที่เกิดเหตุ",
    "แผนการโจมตีจะเริ่มขึ้นในคืนวันเพ็ญ",
    "ข้อมูลถูกเข้ารหัสด้วยอัลกอริทึมโบราณ",
    "กรุงเทพมหานครอมรรัตนโกสินทร์",
    "ความลับระดับสูงสุดห้ามเปิดเผย",
    "เรือดำน้ำลับอยู่ในอ่าวอันดามัน",
]
JSONS = [
    '{"user":"admin","password":"P@ssw0rd"}',
    '{"status":"ok","code":200,"message":"hello"}',
    '{"token":"abc123def","expires":3600}',
    '{"cmd":"decode","args":["base64","hex"]}',
]
URLS = [
    "https://example.com/search?q=decode+now",
    "http://10.0.0.1:8080/admin/login",
    "https://api.th.co/v1/keys?id=42&debug=true",
]
CREDS = [
    "admin:P@ssw0rd123!", "root:toor", "user42:Hunter2#secure",
    "operator:9876543210",
]
UPPER_ALNUM = [
    "HELLOWORLD", "S3CR3TM3SS4G3", "DECODETHISNOW", "CALLME5551234",
    "MISSION911", "ALPHA7BRAVO22", "ECHO6DELTA88", "ZERO91ONE",
]
UPPER_ALPHA = [
    "DECODEME", "TOPSECRET", "BACONBREAKFAST", "CIPHERTEXT", "ATTACKDAWN",
    "THEEAGLELANDS", "FINDTHEKEY",
]
DIGIT_HEAVY = [
    "AGENT007REPORT99", "FLIGHT90210GATE7", "CODE444555666", "ROOM101FLOOR9",
]
DOMAINS = ["สวัสดี.com", "ทีมดีโคด.net", "ประเทศไทย.th", "น่านน้ำ.co"]

POOLS = {
    "flags": FLAGS, "english": ENGLISH, "thai": THAI, "json": JSONS,
    "url": URLS, "creds": CREDS, "upper_alnum": UPPER_ALNUM,
    "upper_alpha": UPPER_ALPHA, "digits": DIGIT_HEAVY, "domain": DOMAINS,
}

ALL_TEXTS = [t for pool in POOLS.values() for t in pool]

# ------------------------------------------------------------------ encoders

BASE36_AL = "0123456789abcdefghijklmnopqrstuvwxyz"
BASE58_AL = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE62_AL = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
BASE45_AL = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
BASE91_AL = ('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
             '!#$%&()*+,./:;<=>?@[]^_`{|}~"')
BASE92_AL = ("!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "[\\]^_abcdefghijklmnopqrstuvwxyz{|}")
MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.",
}
NATO = {
    "A": "Alpha", "B": "Bravo", "C": "Charlie", "D": "Delta", "E": "Echo",
    "F": "Foxtrot", "G": "Golf", "H": "Hotel", "I": "India", "J": "Juliett",
    "K": "Kilo", "L": "Lima", "M": "Mike", "N": "November", "O": "Oscar",
    "P": "Papa", "Q": "Quebec", "R": "Romeo", "S": "Sierra", "T": "Tango",
    "U": "Uniform", "V": "Victor", "W": "Whiskey", "X": "Xray", "Y": "Yankee",
    "Z": "Zulu", "0": "Zero", "1": "One", "2": "Two", "3": "Three",
    "4": "Four", "5": "Five", "6": "Six", "7": "Seven", "8": "Eight",
    "9": "Nine",
}
BACON = {
    "A": "AAAAA", "B": "AAAAB", "C": "AAABA", "D": "AAABB", "E": "AABAA",
    "F": "AABAB", "G": "AABBA", "H": "AABBB", "I": "ABAAA", "J": "ABAAB",
    "K": "ABABA", "L": "ABABB", "M": "ABBAA", "N": "ABBAB", "O": "ABBBA",
    "P": "ABBBB", "Q": "BAAAA", "R": "BAAAB", "S": "BAABA", "T": "BAABB",
    "U": "BABAA", "V": "BABAB", "W": "BABBA", "X": "BABBB", "Y": "BBAAA",
    "Z": "BBAAB",
}

def _int_to_alpha(number: int, alphabet: str) -> str:
    base, out = len(alphabet), []
    while True:
        number, rem = divmod(number, base)
        out.append(alphabet[rem])
        if number == 0:
            break
    return "".join(reversed(out))

def _int_encode(text: str, alphabet: str) -> str:
    raw = text.encode("utf-8")
    prefix = alphabet[0] * (len(raw) - len(raw.lstrip(b"\x00")))
    return prefix + _int_to_alpha(int.from_bytes(raw, "big"), alphabet)

def _b64s(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def enc_base2(t): return format(int.from_bytes(t.encode(), "big"), "b").zfill(len(t.encode()) * 8)
def enc_base16(t): return t.encode().hex()
def enc_base32(t): return base64.b32encode(t.encode()).decode().rstrip("=")
def enc_base32hex(t): return enc_base32(t).translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "0123456789ABCDEFGHIJKLMNOPQRSTUV"))
def enc_base36(t): return _int_encode(t, BASE36_AL)
def enc_base58(t): return _int_encode(t, BASE58_AL)
def enc_base62(t): return _int_encode(t, BASE62_AL)
def enc_base64(t): return base64.b64encode(t.encode()).decode()
def enc_base64url(t): return base64.urlsafe_b64encode(t.encode()).decode().rstrip("=")
def enc_base85(t): return base64.b85encode(t.encode()).decode()
def enc_ascii85(t): return base64.a85encode(t.encode(), adobe=False).decode()

Z85_AL = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"

def enc_z85(t: str) -> str:
    raw = t.encode()
    if len(raw) % 4:
        raise ValueError("z85 needs byte length divisible by 4")
    out = []
    for i in range(0, len(raw), 4):
        v = int.from_bytes(raw[i:i + 4], "big")
        out.append("".join(Z85_AL[(v // (85 ** j)) % 85] for j in reversed(range(5))))
    return "".join(out)

def _z85(raw: bytes) -> str:
    out = []
    for i in range(0, len(raw), 4):
        v = int.from_bytes(raw[i:i + 4], "big")
        chunk = [Z85_AL[(v // (85 ** j)) % 85] for j in reversed(range(5))]
        out.append("".join(chunk))
    return "".join(out)

def enc_base45(t: str) -> str:
    raw, out = t.encode(), []
    for i in range(0, len(raw) - 1, 2):
        v = raw[i] | (raw[i + 1] << 8)  # project decoder uses little-endian val
        out.append(BASE45_AL[v % 45] + BASE45_AL[(v // 45) % 45] + BASE45_AL[(v // 2025) % 45])
    if len(raw) % 2:
        b = raw[-1]
        out.append(BASE45_AL[b % 45] + BASE45_AL[b // 45])
    return "".join(out)

def enc_base91(t: str) -> str:
    raw, b, n, out = t.encode(), 0, 0, []
    for byte in raw:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13; n -= 13
            else:
                v = b & 16383; b >>= 14; n -= 14
            out.append(BASE91_AL[v % 91]); out.append(BASE91_AL[v // 91])
    if n:
        out.append(BASE91_AL[b % 91])
        if n > 7 or b > 90:
            out.append(BASE91_AL[b // 91])
    return "".join(out)

def enc_base92(t: str) -> str:
    """Exact inverse of decoders.base_decoders.decode_base92.

    Layout: `npairs` 13-bit body blocks (2 chars each, first char = high),
    then a tail that completes the final 1-2 bytes. After the body the buffer
    holds L = (13*npairs) % 8 leftover bits and U = nbits - 13*npairs data
    bits remain; U must equal 8-L (1 final byte, 2 tail chars) or 16-L
    (2 final bytes, needs L >= 3, 2 tail chars).
    """
    raw = t.encode()
    nbits = 8 * len(raw)
    if not raw:
        return "~"
    layout = None
    for np_ in range(nbits // 13, -1, -1):
        U, L = nbits - 13 * np_, (13 * np_) % 8
        if U == 8 - L and L < 3:          # even tail, 2 chars, 1 final byte
            layout = (np_, L, U, "even1")
            break
        if U == 16 - L and L >= 3:        # even tail, 2 chars, 2 final bytes
            layout = (np_, L, U, "even2")
            break
        if U == 8 - L and L >= 2:         # odd tail, 1 char (6 bits), 1 final byte
            layout = (np_, L, U, "odd")
            break
    if layout is None:
        raise ValueError("base92: no valid layout")
    npairs, L, U, kind = layout
    bits = format(int.from_bytes(raw, "big"), f"0{nbits}b")
    body, pos = [], 0
    for _ in range(npairs):
        v = int(bits[pos:pos + 13], 2); pos += 13
        body.append(BASE92_AL[v // 91]); body.append(BASE92_AL[v % 91])
    uval = int(bits[pos:], 2) if U else 0
    if kind == "even1":
        tail = BASE92_AL[(uval << (5 + L)) // 91] + BASE92_AL[(uval << (5 + L)) % 91]
    elif kind == "even2":
        tail_v = uval << (L - 3)
        tail = BASE92_AL[tail_v // 91] + BASE92_AL[tail_v % 91]
    else:
        tail = BASE92_AL[uval << (L - 2)]
    return "".join(body) + tail

def enc_base100(t): return "".join(chr(0x1F3F7 + b) for b in t.encode())
def enc_reverse(t): return t[::-1]
def enc_morse(t): return " / ".join(" ".join(MORSE[c] for c in w) for w in t.split())
def enc_nato(t): return " ".join(NATO[c] for c in t)
def enc_bacon(t): return "".join(BACON[c] for c in t)

def _rot(t, n):
    return "".join(
        chr((ord(c) - (65 if c.isupper() else 97) + n) % 26 + (65 if c.isupper() else 97))
        if c.isascii() and c.isalpha() else c
        for c in t)

def enc_rot13(t): return _rot(t, 13)
def enc_rot5(t):
    return "".join(chr((int(c) + 5) % 10 + 48) if c.isdigit() else c for c in t)
def enc_rot18(t):
    return "".join(
        chr((int(c) + 5) % 10 + 48) if c.isdigit() else
        (chr((ord(c) - (65 if c.isupper() else 97) + 13) % 26 + (65 if c.isupper() else 97))
         if c.isascii() and c.isalpha() else c)
        for c in t)
def enc_rot47(t):
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in t)
def enc_atbash(t):
    return "".join(
        chr(90 - (ord(c) - 65)) if "A" <= c <= "Z" else
        chr(122 - (ord(c) - 97)) if "a" <= c <= "z" else c
        for c in t)

def enc_xor_singlebyte(t, key=None):
    key = key if key is not None else random.Random().choice(range(0x24, 0x7F))
    return bytes(b ^ key for b in t.encode()).hex()

def enc_url(t): return urllib.parse.quote(t, safe="")
def enc_punycode(t):
    labels = t.split(".")
    return ".".join("xn--" + l.encode("punycode").decode() if not l.isascii() else l for l in labels)
def enc_hex_escape(t): return "".join(f"\\x{b:02x}" for b in t.encode())
def enc_octal_escape(t): return "".join(f"\\{b:o}" for b in t.encode())
def enc_html_num(t): return "".join(f"&#{b};" for b in t.encode())
def enc_qp(t):
    import quopri
    return quopri.encodestring(t.encode()).decode("latin-1").rstrip("\n")

def _compress(t, fn):
    return _b64s(fn(t.encode()))

def enc_gzip(t): return _compress(t, gzip.compress)
def enc_zlib(t): return _compress(t, zlib.compress)
def enc_bzip2(t): return _compress(t, bz2.compress)
def enc_xz(t): return _compress(t, lzma.compress)

def enc_jwt(t, secret=b"benchmark-secret"):
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    payload_json = json.dumps({"msg": t, "iss": "bench"}, separators=(",", ":")).encode()
    payload = base64.urlsafe_b64encode(payload_json).decode().rstrip("=")
    signing = f"{header}.{payload}".encode()
    sig = base64.urlsafe_b64encode(hmac.new(secret, signing, hashlib.sha256).digest()).decode().rstrip("=")
    return f"{header}.{payload}.{sig}"

def enc_brainfuck(t):
    code, cur = [], 0
    for b in t.encode():
        code.append("+" * ((b - cur) % 256) + ".")
        cur = b
    return "".join(code)

def _thai_consonant_count(t): return sum(1 for c in t if c in THAI_CONSONANTS)

def enc_thai_rot(t, shift=None):
    n = len(THAI_CONSONANTS)
    shift = shift if shift is not None else random.Random().randrange(1, n)
    table = {c: THAI_CONSONANTS[(i + shift) % n] for i, c in enumerate(THAI_CONSONANTS)}
    return "".join(table.get(c, c) for c in t)

def enc_thai_atbash(t):
    n = len(THAI_CONSONANTS)
    return "".join(THAI_CONSONANTS[n - 1 - i] if (i := THAI_CONSONANTS.find(c)) >= 0 else c for c in t)

def enc_thai_polybius(t):
    return "".join(_THAI_POLYBIUS_ENC[c] for c in t)

# accept() predicates -------------------------------------------------------

_is_ascii = lambda t: t.isascii()
_has_letters = lambda t: sum(c.isalpha() and c.isascii() for c in t) >= 3
_rotatable = lambda t: sum(c.isalpha() and c.isascii() for c in t) >= 3
_digit3 = lambda t: sum(c.isdigit() for c in t) >= 3

ENCODER_SPECS = {
    # name: (fn, accept, pools, expanding, first_only, match_mode)
    "base2":        (enc_base2, lambda t: t.isascii() and len(t) >= 2, ["flags", "english", "upper_alnum"], True, False, "exact"),
    "base16":       (enc_base16, lambda t: t.isascii() and len(t) >= 2, ["flags", "english", "json", "creds"], True, False, "exact"),
    "base32":       (enc_base32, lambda t: t.isascii() and len(t) >= 2, ["flags", "english", "upper_alnum"], False, False, "exact"),
    "base32hex":    (enc_base32hex, lambda t: t.isascii() and len(t) >= 2, ["flags", "english", "upper_alnum"], False, False, "exact"),
    "base36":       (enc_base36, lambda t: len(t) >= 2 and not t[0].isdigit() or len(t) >= 2, ["flags", "english", "upper_alnum"], False, False, "exact"),
    "base45":       (enc_base45, lambda t: t.isascii() and len(t) >= 2, ["flags", "english", "json"], False, False, "exact"),
    "base58":       (enc_base58, lambda t: len(t) >= 2, ["flags", "english", "json", "thai"], False, False, "exact"),
    "base62":       (enc_base62, lambda t: len(t) >= 2, ["flags", "english", "json", "creds"], False, False, "exact"),
    "base64":       (enc_base64, lambda t: len(t) >= 2, ["flags", "english", "thai", "json", "creds", "url"], False, False, "exact"),
    "base64url":    (enc_base64url, lambda t: len(t) >= 2, ["flags", "english", "thai", "json"], False, False, "exact"),
    "base85":       (enc_base85, lambda t: t.isascii() and len(t) >= 3, ["flags", "english", "creds"], False, False, "exact"),
    "ascii85":      (enc_ascii85, lambda t: t.isascii() and len(t) >= 3, ["flags", "english", "creds"], False, False, "exact"),
    "z85":          (enc_z85, lambda t: len(t.encode()) % 4 == 0 and len(t) >= 4, ["flags", "english", "upper_alnum"], False, False, "exact"),
    "base91":       (enc_base91, lambda t: t.isascii() and len(t) >= 2, ["flags", "english", "creds"], False, False, "exact"),
    "base92":       (enc_base92, lambda t: t.isascii() and len(t) >= 2, ["flags", "english", "creds"], False, False, "exact"),
    "base100":      (enc_base100, lambda t: len(t) >= 2, ["flags", "english", "thai", "json"], False, False, "exact"),
    "reverse":      (enc_reverse, lambda t: len(t) >= 4, ["flags", "english", "thai", "upper_alnum"], False, False, "exact"),
    "morse":        (enc_morse, lambda t: len(t) >= 3 and re.fullmatch(r"[A-Z0-9 ]+", t), ["upper_alnum", "upper_alpha"], True, False, "exact"),
    "nato":         (enc_nato, lambda t: len(t) >= 2 and re.fullmatch(r"[A-Z0-9]+", t), ["upper_alnum"], True, False, "exact"),
    "bacon":        (enc_bacon, lambda t: len(t) >= 2 and re.fullmatch(r"[A-Z]+", t), ["upper_alpha"], True, False, "exact"),
    "rot13":        (enc_rot13, _rotatable, ["flags", "english", "upper_alnum", "upper_alpha"], False, False, "exact"),
    "rot5":         (enc_rot5, _digit3, ["digits", "upper_alnum", "json", "creds"], False, False, "exact"),
    "rot18":        (enc_rot18, lambda t: _digit3(t) and _rotatable(t), ["digits", "upper_alnum", "creds"], False, False, "exact"),
    "rot47":        (enc_rot47, lambda t: t.isascii() and _rotatable(t), ["flags", "english", "creds", "json"], False, False, "exact"),
    "atbash":       (enc_atbash, _rotatable, ["flags", "english", "upper_alnum", "upper_alpha"], False, False, "exact"),
    "xor_singlebyte": (enc_xor_singlebyte, lambda t: t.isascii() and len(t) >= 6, ["flags", "english", "creds"], True, False, "exact"),
    "url":          (enc_url, lambda t: t.isascii() and len(t) >= 4, ["english", "json", "url", "creds"], True, False, "exact"),
    "punycode":     (enc_punycode, lambda t: not t.isascii() and "." in t, ["domain"], False, True, "exact"),
    "hex_escape":   (enc_hex_escape, lambda t: t.isascii() and len(t) >= 2, ["flags", "english", "creds"], True, False, "exact"),
    "octal_escape": (enc_octal_escape, lambda t: t.isascii() and len(t) >= 2, ["flags", "english", "creds"], True, False, "exact"),
    "html_numeric": (enc_html_num, lambda t: t.isascii() and len(t) >= 2, ["flags", "english", "creds", "url"], True, False, "exact"),
    "html_entity":  (lambda t: __import__("html").escape(t, quote=True), lambda t: t.isascii() and len(t) >= 4 and any(c in "<>&" for c in t), ["json", "creds", "english"], True, False, "exact"),
    "quoted_printable": (enc_qp, lambda t: len(t) >= 4 and (not t.isascii() or "=" in t), ["english", "thai", "creds"], True, False, "exact"),
    "gzip":         (enc_gzip, lambda t: len(t.encode()) >= 8, ["flags", "english", "thai", "json"], False, False, "exact"),
    "zlib":         (enc_zlib, lambda t: len(t.encode()) >= 8, ["flags", "english", "thai", "json"], False, False, "exact"),
    "bzip2":        (enc_bzip2, lambda t: len(t.encode()) >= 8, ["flags", "english", "json"], False, False, "exact"),
    "xz":           (enc_xz, lambda t: len(t.encode()) >= 8, ["flags", "english", "json"], False, False, "exact"),
    "jwt":          (enc_jwt, lambda t: t.isascii() and 3 <= len(t) <= 60, ["flags", "english", "creds"], False, True, "contains"),
    "brainfuck":    (enc_brainfuck, lambda t: t.isascii() and 4 <= len(t) <= 12, ["flags", "upper_alnum", "english"], True, True, "exact"),
    "thai_rot":     (enc_thai_rot, lambda t: _thai_consonant_count(t) >= 4, ["thai"], False, False, "exact"),
    "thai_atbash":  (enc_thai_atbash, lambda t: _thai_consonant_count(t) >= 4, ["thai"], False, False, "exact"),
    "thai_polybius": (enc_thai_polybius, lambda t: len(t) >= 2 and all(c in THAI_POLYBIUS_CONSONANTS for c in t), ["thai_poly"], False, False, "exact"),
}

EASY = ["base64", "base32", "base16", "base64url", "base2", "rot13", "reverse", "url", "morse", "hex_escape"]
NORMAL = ["base36", "base45", "base58", "base62", "base85", "ascii85", "z85", "base91", "base92",
          "base100", "base32hex", "rot5", "rot18", "rot47", "atbash", "bacon", "nato",
          "octal_escape", "html_numeric", "html_entity", "quoted_printable", "punycode", "jwt",
          "brainfuck", "gzip", "zlib", "bzip2", "xz", "xor_singlebyte",
          "thai_rot", "thai_atbash", "thai_polybius"]

POOLS["thai_poly"] = ["".join(random.Random(i).choice(THAI_POLYBIUS_CONSONANTS) for _ in range(rng_len))
                      for i, rng_len in enumerate([8, 10, 12, 9, 11, 7, 10, 8])]

# ------------------------------------------------------------- self-verify

def self_verify() -> tuple[dict, list[str]]:
    """Encode a probe with each encoder; keep it only if the system's own
    decode_once() can invert it back to the probe text."""
    ok, bad = {}, []
    poly_probe = "".join(random.Random(7).choice(THAI_POLYBIUS_CONSONANTS) for _ in range(8))
    probes = ["flag{test_1234}", "flag{test_12345}", "Attack at dawn now",
              "S3CR3T911", "สวัสดีครับ", "HELLOWORLD", "admin:P@ss",
              "https://a.b?q=1 2", "สวัสดี.com",
              '{"user":"admin","password":"P@ssw0rd"}',
              '<script>alert(1)&x</script>', poly_probe]
    def _match(c, p, m):
        c, p = c.strip(), p.strip()
        return (p in c) if m == "contains" else (c == p)
    for name, spec in ENCODER_SPECS.items():
        fn, accept, pools, _exp, _fo, mode = spec
        probe = next((p for p in probes if accept(p)), None)
        if probe is None:
            bad.append((name, "no probe satisfies accept()"))
            continue
        try:
            encoded = fn(probe)
        except Exception as e:
            bad.append((name, f"encoder raised {e!r}"))
            continue
        inverted = [dname for dname, decoded in decode_once(encoded) if _match(decoded, probe, mode)]
        if inverted:
            ok[name] = inverted
        else:
            bad.append((name, f"no decoder inverts encoding of {probe!r}"))
    return ok, bad

# ------------------------------------------------------------- case builder

def build_cases(rng: random.Random, counts: dict[str, int]) -> list[dict]:
    cases = []
    ok_names = [n for n in ENCODER_SPECS]

    def add_single(name: str, tier: str):
        fn, accept, pools, exp, fo, mode = ENCODER_SPECS[name]
        for _ in range(60):
            pt = rng.choice(POOLS[rng.choice(pools)])
            if not accept(pt):
                continue
            try:
                encoded = fn(pt)
            except Exception:
                break
            if encoded and encoded != pt:
                cases.append({"tier": tier, "input": encoded, "expected": pt,
                              "true_chain": [name], "mode": mode})
                return
        # fallback: scan every pool
        for pt in ALL_TEXTS + POOLS["thai_poly"]:
            if accept(pt):
                try:
                    encoded = fn(pt)
                except Exception:
                    continue
                if encoded and encoded != pt:
                    cases.append({"tier": tier, "input": encoded, "expected": pt,
                                  "true_chain": [name], "mode": mode})
                    return

    def add_chain(tier: str, depth: int):
        max_expand = 3 if depth <= 3 else (2 if depth == 4 else 1)
        for _ in range(400):
            pt = rng.choice(ALL_TEXTS + POOLS["thai_poly"])
            text, used, expanding = pt, [], 0
            for step in range(depth):
                options = []
                for name in ok_names:
                    fn, accept, pools, exp, first_only, mode = ENCODER_SPECS[name]
                    if name in used and name in ONCE_PER_CHAIN_SCHEMES:
                        continue
                    if step > 0 and first_only:
                        continue
                    if accept(text):
                        options.append(name)
                if not options:
                    break
                rng.shuffle(options)
                placed = False
                for name in options:
                    fn, accept, pools, exp, first_only, mode = ENCODER_SPECS[name]
                    if ENCODER_SPECS[name][3] and expanding >= max_expand:
                        continue
                    try:
                        nxt = fn(text)
                    except Exception:
                        continue
                    if not nxt or nxt == text or len(nxt) > 3000:
                        continue
                    used.append(name)
                    if ENCODER_SPECS[name][3]:
                        expanding += 1
                    text = nxt
                    placed = True
                    break
                if not placed:
                    break
            else:
                cases.append({"tier": tier, "input": text, "expected": pt,
                              "true_chain": used, "mode": "exact"})
                return
        # could not build; ignore (counts handled by caller)

    for _ in range(counts.get("easy", 0)):
        add_single(rng.choice([n for n in EASY if n in ENCODER_SPECS]), "easy")
    for _ in range(counts.get("normal", 0)):
        add_single(rng.choice([n for n in NORMAL if n in ENCODER_SPECS]), "normal")
    for _ in range(counts.get("hard", 0)):
        add_chain("hard", rng.choice([2, 2, 3, 3, 3]))
    for _ in range(counts.get("extreme", 0)):
        add_chain("extreme", rng.choice([4, 4, 5, 5, 6]))

    # top-up any shortfall with easy singles so total is exact
    target = sum(counts.values())
    guard = 0
    while len(cases) < target and guard < 500:
        add_single(rng.choice([n for n in EASY + NORMAL if n in ENCODER_SPECS]), "topup")
        guard += 1
    return cases[:target]

# ------------------------------------------------------------------- runner

_WORKER_CFG = {"max_depth": 8, "beam_size": 40, "verify": False}
_VERIFIER = None

def _init_worker(max_depth: int, beam_size: int, verify: bool = False) -> None:
    global _VERIFIER
    _WORKER_CFG["max_depth"], _WORKER_CFG["beam_size"], _WORKER_CFG["verify"] = max_depth, beam_size, verify
    if verify:
        from core.verifier import VerifierRanker
        _VERIFIER = VerifierRanker.load()

def match(candidate: str, expected: str, mode: str) -> bool:
    c, e = candidate.strip(), expected.strip()
    return (e in c) if mode == "contains" else (c == e)

def _run_case(case: dict) -> dict:
    started = time.perf_counter()
    try:
        cands = auto_decode(case["input"], max_depth=_WORKER_CFG["max_depth"],
                            beam_size=_WORKER_CFG["beam_size"])
    except Exception as e:
        cands = []
        case["error"] = repr(e)
    if _WORKER_CFG.get("verify") and _VERIFIER is not None and _VERIFIER.available:
        cands = _VERIFIER.rerank(cands)
    elapsed = time.perf_counter() - started
    texts = [c.text for c in cands]
    chains = [list(c.chain) for c in cands]
    rank = next((i for i, t in enumerate(texts) if match(t, case["expected"], case["mode"])), -1)
    return {
        **{k: case[k] for k in ("tier", "input", "expected", "true_chain", "mode")},
        "n_candidates": len(cands),
        "rank": rank,
        "top1_text": texts[0] if texts else None,
        "top1_chain": chains[0] if chains else None,
        "time_s": round(elapsed, 3),
        "input_len": len(case["input"]),
    }

def run(cases: list[dict], log_every: int = 50, max_depth: int = 8, beam_size: int = 40,
        workers: int = 6, verify: bool = False) -> tuple[dict, list]:
    from concurrent.futures import ProcessPoolExecutor
    results = []
    t0 = time.perf_counter()
    if workers > 1:
        with ProcessPoolExecutor(max_workers=workers, initializer=_init_worker,
                                 initargs=(max_depth, beam_size, verify)) as ex:
            for idx, res in enumerate(ex.map(_run_case, cases, chunksize=1), 1):
                results.append(res)
                if idx % log_every == 0:
                    done_top1 = sum(1 for r in results if r["rank"] == 0)
                    print(f"[{idx}/{len(cases)}] top1={done_top1}/{idx} ({100*done_top1/idx:.1f}%) "
                          f"elapsed={time.perf_counter()-t0:.1f}s", flush=True)
    else:
        _init_worker(max_depth, beam_size, verify)
        results = [_run_case(c) for c in cases]
    return summarize(results), results

def summarize(results: list[dict]) -> dict:
    def rate(rs, k):
        return round(100 * sum(1 for r in rs if k(r)) / max(len(rs), 1), 1)
    tiers = {}
    for tier in sorted({r["tier"] for r in results}):
        rs = [r for r in results if r["tier"] == tier]
        tiers[tier] = {
            "count": len(rs),
            "top1": rate(rs, lambda r: r["rank"] == 0),
            "top3": rate(rs, lambda r: 0 <= r["rank"] < 3),
            "found_anywhere": rate(rs, lambda r: r["rank"] >= 0),
            "avg_time_s": round(sum(r["time_s"] for r in rs) / max(len(rs), 1), 3),
        }
    # failure hotspots: which true outermost encoder failed most
    hotspot = {}
    for r in results:
        if r["rank"] != 0 and r["true_chain"]:
            key = "+".join(r["true_chain"])
            hotspot[key] = hotspot.get(key, 0) + 1
    worst_time = sorted(results, key=lambda r: -r["time_s"])[:5]
    ranking_failures = sum(1 for r in results if r["rank"] > 0)
    search_failures = sum(1 for r in results if r["rank"] < 0)
    return {
        "total": len(results),
        "top1_pct": rate(results, lambda r: r["rank"] == 0),
        "top3_pct": rate(results, lambda r: 0 <= r["rank"] < 3),
        "found_anywhere_pct": rate(results, lambda r: r["rank"] >= 0),
        "ranking_failures (correct candidate existed but not ranked #1)": ranking_failures,
        "search_failures (correct candidate never generated)": search_failures,
        "avg_time_s": round(sum(r["time_s"] for r in results) / max(len(results), 1), 3),
        "max_time_s": round(max(r["time_s"] for r in results), 3) if results else 0,
        "by_tier": tiers,
        "failure_hotspots_top20": dict(sorted(hotspot.items(), key=lambda kv: -kv[1])[:20]),
        "slowest_cases": [{"input": w["input"][:60], "true_chain": w["true_chain"], "time_s": w["time_s"]} for w in worst_time],
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--easy", type=int, default=250)
    ap.add_argument("--normal", type=int, default=250)
    ap.add_argument("--hard", type=int, default=300)
    ap.add_argument("--extreme", type=int, default=150)
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--depth", type=int, default=8)
    ap.add_argument("--beam", type=int, default=40)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--verify", action="store_true", help="re-rank candidates with the AI verifier")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    print("== self-verification of encoders ==", flush=True)
    verified, bad = self_verify()
    for name, why in bad:
        print(f"  EXCLUDED {name}: {why}")
    print(f"  {len(verified)}/{len(ENCODER_SPECS)} encoders verified", flush=True)
    bad_names = {name for name, _ in bad}
    for name in bad_names:
        ENCODER_SPECS.pop(name, None)

    counts = {"easy": args.easy, "normal": args.normal, "hard": args.hard, "extreme": args.extreme}
    print(f"== building {sum(counts.values())} cases (seed={args.seed}) ==", flush=True)
    cases = build_cases(rng, counts)
    print(f"  built {len(cases)} cases", flush=True)

    print(f"== running benchmark (depth={args.depth}, beam={args.beam}, workers={args.workers}, verify={args.verify}) ==", flush=True)
    report, results = run(cases, max_depth=args.depth, beam_size=args.beam, workers=args.workers, verify=args.verify)

    out_dir = Path(__file__).resolve().parent / "reports"
    out_dir.mkdir(exist_ok=True)

    failures = [r for r in results if r["rank"] != 0][:300]
    with open(out_dir / "benchmark_failures.json", "w", encoding="utf-8") as f:
        json.dump(failures, f, ensure_ascii=False, indent=2)

    print(json.dumps(report, ensure_ascii=False, indent=2))

    with open(out_dir / "benchmark_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()
