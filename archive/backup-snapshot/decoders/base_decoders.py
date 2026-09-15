from __future__ import annotations
import base64, binascii, hashlib, re, urllib.parse
from core.registry import register_decoder
from core.heuristics import _log_debug, bytes_to_text, is_effectively_binary

BASE36_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
BASE45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
Z85_ALPHABET    = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
BASE91_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
BASE92_ALPHABET = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}"
BASE100_START, BASE100_END = 0x1F3F7, 0x1F4F6

def add_base64_padding(value: str) -> str:
    return value + ("=" * ((4 - len(value) % 4) % 4))

def decode_int_alphabet(value: str, alphabet: str) -> bytes | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 2 or any(ch not in alphabet for ch in compact): return None
    base, number = len(alphabet), 0
    for ch in compact: number = number * base + alphabet.index(ch)
    leading_zeroes = len(compact) - len(compact.lstrip(alphabet[0]))
    raw = b"\x00" * leading_zeroes
    if number: raw += number.to_bytes((number.bit_length() + 7) // 8, "big")
    return raw or None

@register_decoder(name="base2", category="base")
def decode_base2(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if not compact or len(compact) % 8 != 0 or not set(compact).issubset({'0','1'}): return None
    try:
        raw = int(compact, 2).to_bytes(len(compact) // 8, byteorder='big')
        text = bytes_to_text(raw)
        if text and not is_effectively_binary(text): return text
        return None
    except ValueError: return None

@register_decoder(name="base16", category="base")
def decode_base16(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 2 or len(compact) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", compact): return None
    res = bytes_to_text(bytes.fromhex(compact))
    return res if res and not is_effectively_binary(res) else None

@register_decoder(name="base32", category="base")
def decode_base32(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value).replace('-','').replace('.','').replace('_','')
    if '%' in compact or '+' in compact:
        try:
            unq = urllib.parse.unquote(compact)
            if unq and unq != compact: compact = unq
        except Exception as e: _log_debug(f"decode_base32: unquote failed: {e!r}")
    s = compact.upper().rstrip('=')
    pad32 = lambda t: t + ('=' * ((-len(t)) % 8))
    if re.fullmatch(r"[A-Z2-7]+=*", s) and len(s) >= 2:
        try:
            decoded = bytes_to_text(base64.b32decode(pad32(s), casefold=True))
            if decoded is not None: return decoded
        except (binascii.Error, ValueError): pass
    alt = re.sub(r"[\-_.]", "", value).upper().rstrip('=')
    if alt != s and re.fullmatch(r"[A-Z2-7]+=*", alt):
        try:
            decoded = bytes_to_text(base64.b32decode(pad32(alt), casefold=True))
            if decoded is not None: return decoded
        except Exception as e: _log_debug(f"decode_base32: forgiving variant failed: {e!r}")
    BASE32HEX, STANDARD_B32 = "0123456789ABCDEFGHIJKLMNOPQRSTUV", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    cleaned = re.sub(r"=+", "", s)
    if re.fullmatch(r"[0-9A-V]+", cleaned) and len(cleaned) >= 2:
        try:
            mapped = ''.join(STANDARD_B32[BASE32HEX.index(ch)] for ch in cleaned)
            decoded = bytes_to_text(base64.b32decode(pad32(mapped), casefold=True))
            if decoded is not None: return decoded
        except Exception as e: _log_debug(f"decode_base32: base32hex mapping failed: {e!r}")
    return None

@register_decoder(name="base36", category="base")
def decode_base36(v: str) -> str | None:
    raw = decode_int_alphabet(v.lower(), BASE36_ALPHABET); return bytes_to_text(raw) if raw else None

@register_decoder(name="base45", category="base")
def decode_base45(value: str) -> str | None:
    compact = value.strip().replace("\n","").replace("\r","").upper()
    if not compact or any(ch not in BASE45_ALPHABET for ch in compact): return None
    table = {ch: i for i, ch in enumerate(BASE45_ALPHABET)}
    output = bytearray()
    for i in range(0, len(compact), 3):
        chunk = compact[i:i+3]
        if len(chunk) == 3:
            val = table[chunk[0]] + table[chunk[1]] * 45 + table[chunk[2]] * 45 * 45
            if val > 0xFFFF: return None
            output.extend(val.to_bytes(2, "big"))
        elif len(chunk) == 2:
            val = table[chunk[0]] + table[chunk[1]] * 45
            if val > 0xFF: return None
            output.extend(val.to_bytes(1, "big"))
        else: return None
    return bytes_to_text(bytes(output))

@register_decoder(name="base58", category="base")
def decode_base58(v: str) -> str | None:
    raw = decode_int_alphabet(v, BASE58_ALPHABET); return bytes_to_text(raw) if raw else None

@register_decoder(name="base58check", category="base")
def decode_base58check(value: str) -> str | None:
    raw = decode_int_alphabet(value, BASE58_ALPHABET)
    if raw is None or len(raw) < 5: return None
    payload, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum: return None
    text = bytes_to_text(payload)
    if text is not None: return text
    if len(payload) > 1: return bytes_to_text(payload[1:])
    return None

@register_decoder(name="base62", category="base")
def decode_base62(v: str) -> str | None:
    raw = decode_int_alphabet(v, BASE62_ALPHABET); return bytes_to_text(raw) if raw else None

@register_decoder(name="base64", category="base")
def decode_base64(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 4 or not re.fullmatch(r"[A-Za-z0-9+/]+=*", compact): return None
    try: return bytes_to_text(base64.b64decode(add_base64_padding(compact), validate=True))
    except (binascii.Error, ValueError): return None

@register_decoder(name="base64url", category="base")
def decode_base64url(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 4 or not re.fullmatch(r"[A-Za-z0-9_-]+=*", compact): return None
    try: return bytes_to_text(base64.urlsafe_b64decode(add_base64_padding(compact)))
    except (binascii.Error, ValueError): return None

@register_decoder(name="base85", category="base")
def decode_base85(v: str) -> str | None:
    c = v.strip()
    if len(c) < 5: return None
    try: return bytes_to_text(base64.b85decode(c))
    except (binascii.Error, ValueError): return None

@register_decoder(name="ascii85", category="base")
def decode_ascii85(v: str) -> str | None:
    c = v.strip()
    if len(c) < 5: return None
    try: return bytes_to_text(base64.a85decode(c, adobe=False))
    except (binascii.Error, ValueError): return None

@register_decoder(name="z85", category="base")
def decode_z85(value: str) -> str | None:
    compact = value.strip().replace("\n","").replace("\r","")
    if len(compact) % 5 != 0 or any(ch not in Z85_ALPHABET for ch in compact): return None
    table = {ch: i for i, ch in enumerate(Z85_ALPHABET)}; output = bytearray()
    for i in range(0, len(compact), 5):
        val = sum(table[c] * (85 ** (4 - j)) for j, c in enumerate(compact[i:i+5]))
        if val > 0xFFFFFFFF: return None
        output.extend(val.to_bytes(4, "big"))
    return bytes_to_text(bytes(output))

@register_decoder(name="base91", category="base")
def decode_base91(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 2 or any(ch not in BASE91_ALPHABET for ch in compact): return None
    table = {ch: i for i, ch in enumerate(BASE91_ALPHABET)}
    output = bytearray(); accumulator, bit_count, pending = 0, 0, -1
    for ch in compact:
        current = table[ch]
        if pending < 0: pending = current; continue
        pending += current * 91
        accumulator |= pending << bit_count
        bit_count += 13 if (pending & 8191) > 88 else 14
        while bit_count > 7: output.append(accumulator & 255); accumulator >>= 8; bit_count -= 8
        pending = -1
    if pending >= 0: output.append((accumulator | pending << bit_count) & 255)
    return bytes_to_text(bytes(output))

@register_decoder(name="base92", category="base")
def decode_base92(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if compact == "~": return ""
    if len(compact) < 2 or any(ch not in BASE92_ALPHABET for ch in compact): return None
    try:
        decoding = {ch: i for i, ch in enumerate(BASE92_ALPHABET)}
        output = bytearray(); buffer, length = 0, 0
        if len(compact) % 2:
            tail_bits, tail, body = 6, decoding[compact[-1]], compact[:-1]
        else:
            tail_bits, tail, body = 13, decoding[compact[-2]] * 91 + decoding[compact[-1]], compact[:-2]
        for index in range(0, len(body), 2):
            block = decoding[body[index]] * 91 + decoding[body[index + 1]]
            buffer = (buffer << 13) | block; length += 13
            size, length = divmod(length, 8)
            output.extend((buffer >> length).to_bytes(size, "big")); buffer &= (1 << length) - 1
        missing = 8 - length; shift = tail_bits - missing
        byte_count = 1 if shift < 8 else 2
        if shift >= 8: shift -= 8; missing += 8
        if shift < 0: return None
        buffer = (buffer << missing) | (tail >> shift); output.extend(buffer.to_bytes(byte_count, "big"))
        if tail & ((1 << shift) - 1): return None
        return bytes_to_text(bytes(output))
    except (OverflowError, KeyError, ValueError): return None

@register_decoder(name="base100", category="base")
def decode_base100(value: str) -> str | None:
    compact = re.sub(r"\s+", "", value)
    if len(compact) < 2: return None
    codepoints = [ord(ch) for ch in compact]
    if not all(BASE100_START <= cp <= BASE100_END for cp in codepoints): return None
    try: return bytes_to_text(bytes(cp - BASE100_START for cp in codepoints))
    except ValueError: return None
