import os, sys, json, base64, gzip, bz2, lzma, zlib, binascii

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.registry import get_all_decoders
from core.engine import auto_decode
from core.heuristics import rot5, rot18, rot47, atbash
from decoders.base_decoders import (
    decode_base2, decode_base16, decode_base32, decode_base36, decode_base45,
    decode_base58, decode_base58check, decode_base62, decode_base64, decode_base64url,
    decode_base85, decode_ascii85, decode_z85, decode_base91, decode_base92,
    decode_base100
)
from decoders.ciphers import (
    decode_morse, decode_nato_phonetic, decode_bacon, decode_reverse, decode_xor_multibyte
)
from decoders.bitwise import decode_xor_singlebyte, decode_xor_multikey
from decoders.compression import decode_gzip, decode_bzip2, decode_xz, decode_zlib
from decoders.web_decoders import (
    decode_url, decode_punycode, decode_hex_escape, decode_octal_escape,
    decode_html_numeric_entity, decode_html_entity, decode_quoted_printable
)

Z85_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"


def encode_base36(data: bytes) -> str:
    alphabet = '0123456789abcdefghijklmnopqrstuvwxyz'
    num = int.from_bytes(data, 'big')
    if num == 0:
        return '0'
    out = ''
    while num > 0:
        num, rem = divmod(num, 36)
        out = alphabet[rem] + out
    return out


def encode_base45(data: bytes) -> str:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
    out = ''
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            val = data[i] + data[i+1] * 256
            out += alphabet[val % 45] + alphabet[(val // 45) % 45] + alphabet[val // (45 * 45)]
        else:
            val = data[i]
            out += alphabet[val % 45] + alphabet[val // 45]
    return out


def encode_base58(data: bytes) -> str:
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(data, 'big')
    if num == 0:
        return alphabet[0]
    out = ''
    while num > 0:
        num, rem = divmod(num, 58)
        out = alphabet[rem] + out
    out = alphabet[0] * len(data[:len(data) - len(data.lstrip(b'\x00'))]) + out
    return out


def encode_base62(data: bytes) -> str:
    alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    num = int.from_bytes(data, 'big')
    if num == 0:
        return alphabet[0]
    out = ''
    while num > 0:
        num, rem = divmod(num, 62)
        out = alphabet[rem] + out
    return out


def encode_z85(data: bytes) -> str:
    if len(data) % 4 != 0:
        raise ValueError('z85 requires length multiple of 4')
    out = ''
    for i in range(0, len(data), 4):
        val = int.from_bytes(data[i:i+4], 'big')
        chars = []
        for _ in range(5):
            chars.append(Z85_ALPHABET[val % 85])
            val //= 85
        out += ''.join(reversed(chars))
    return out


def encode_base100(data: bytes) -> str:
    return ''.join(chr(0x1F3F7 + b) for b in data)


def encode_xor_singlebyte(data: bytes, key: int) -> str:
    return bytes(b ^ key for b in data).hex()


def encode_xor_multikey(data: bytes, key: bytes) -> str:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data)).hex()


def encode_xor_multibyte(data: bytes, key: bytes) -> str:
    # return latin1 string for raw payload
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data)).decode('latin-1')


cases = []

cases += [
    ('base2', decode_base2, 'Hello', lambda: '0100100001100101011011000110110001101111'),
    ('base16', decode_base16, 'Hello World', lambda: b'Hello World'.hex()),
    ('base32', decode_base32, 'Hello World', lambda: base64.b32encode(b'Hello World').decode()),
    ('base36', decode_base36, 'Hello World', lambda: encode_base36(b'Hello World')),
    ('base45', decode_base45, 'Hello World', lambda: encode_base45(b'Hello World')),
    ('base58', decode_base58, 'Hello World', lambda: encode_base58(b'Hello World')),
    ('base62', decode_base62, 'Hello World', lambda: encode_base62(b'Hello World')),
    ('base64', decode_base64, 'Hello World', lambda: base64.b64encode(b'Hello World').decode()),
    ('base64url', decode_base64url, 'Hello-World', lambda: base64.urlsafe_b64encode(b'Hello-World').decode().rstrip('=')),
    ('base85', decode_base85, 'Hello World', lambda: base64.b85encode(b'Hello World').decode()),
    ('ascii85', decode_ascii85, 'Hello World', lambda: base64.a85encode(b'Hello World').decode()),
    ('z85', decode_z85, 'Test', lambda: encode_z85(b'Test')),
    ('base100', decode_base100, 'Foo', lambda: encode_base100(b'Foo')),
    ('morse', decode_morse, 'TEST', lambda: '- . ... -'),
    ('reverse', lambda v: v[::-1], 'world', lambda: 'dlrow'),
    ('atbash', atbash, 'hello', lambda: 'svool'),
    ('rot5', rot5, '5678', lambda: '0123'),
    ('rot18', rot18, 'HELLO', lambda: 'URYYB'),
    ('rot47', rot47, 'Hello', lambda: 'w6==@'),
    ('nato_phonetic', decode_nato_phonetic, 'ABC', lambda: 'alpha bravo charlie'),
    ('bacon', decode_bacon, 'AB', lambda: 'AAAAA AAAAB'),
    ('url', decode_url, 'Hello World', lambda: 'Hello%20World'),
    ('punycode', decode_punycode, '例子.测试', lambda: 'xn--fsqu00a.xn--0zwm56d'),
    ('hex_escape', decode_hex_escape, 'Hello', lambda: '\\x48\\x65\\x6c\\x6c\\x6f'),
    ('octal_escape', decode_octal_escape, 'Hello', lambda: '\\110\\145\\154\\154\\157'),
    ('html_numeric_entity', decode_html_numeric_entity, 'Hello', lambda: '&#72;&#101;&#108;&#108;&#111;'),
    ('html_entity', decode_html_entity, '<div>', lambda: '&lt;div&gt;'),
    ('quoted_printable', decode_quoted_printable, 'Hello World!', lambda: 'Hello=20World=21'),
    ('gzip', decode_gzip, 'Hello World', lambda: base64.b64encode(gzip.compress(b'Hello World')).decode()),
    ('bzip2', decode_bzip2, 'Hello World', lambda: base64.b64encode(bz2.compress(b'Hello World')).decode()),
    ('xz', decode_xz, 'Hello World', lambda: base64.b64encode(lzma.compress(b'Hello World')).decode()),
    ('zlib', decode_zlib, 'Hello World', lambda: base64.b64encode(zlib.compress(b'Hello World')).decode()),
    ('xor_singlebyte', decode_xor_singlebyte, 'This is a secret message that is long enough.', lambda: encode_xor_singlebyte(b'This is a secret message that is long enough.', 42)),
    ('xor_multikey', decode_xor_multikey, 'This is a secret message that is long enough for multikey decoding.', lambda: encode_xor_multikey(b'This is a secret message that is long enough for multikey decoding.', b'key')),
    ('xor_multibyte', decode_xor_multibyte, 'This is a secret message that is long enough for multibyte XOR.', lambda: encode_xor_multibyte(b'This is a secret message that is long enough for multibyte XOR.', b'key')),
]

chain_cases = [
    ('base64_morse', 'TEST', lambda: base64.b64encode(b'- . ... -').decode(), 'TEST'),
    ('base64_gzip', 'Hello World', lambda: base64.b64encode(gzip.compress(b'Hello World')).decode(), 'Hello World'),
    ('base64_xor', 'Short secret message for XOR.', lambda: base64.b64encode(bytes(b ^ 42 for b in b'Short secret message for XOR.')).decode(), 'Short secret message for XOR.'),
]

report = []
for name, func, expected, payload_fn in cases:
    payload = payload_fn()
    try:
        result = func(payload)
    except Exception as e:
        result = f'ERROR: {e!r}'
    report.append((name, payload, expected, result, result == expected))

chain_report = []
for name, expected, payload_fn, expected_text in chain_cases:
    payload = payload_fn()
    try:
        candidates = auto_decode(payload, max_depth=4, beam_size=50)
        top = candidates[0].text if candidates else None
    except Exception as e:
        top = f'ERROR: {e!r}'
    chain_report.append((name, payload, expected_text, top, top == expected_text))

all_decoder_names = [d['name'] for d in get_all_decoders()]
missing = sorted(set(['morse','base64','base16','url','gzip','xor_singlebyte','xor_multikey','zlib']) - set(all_decoder_names))

print(json.dumps({
    'summary': {
        'simple_cases': len(report),
        'simple_passed': sum(1 for r in report if r[4]),
        'chain_cases': len(chain_report),
        'chain_passed': sum(1 for r in chain_report if r[4]),
        'available_decoders': len(all_decoder_names),
        'missing_decoders': missing,
    },
    'simple_results': report,
    'chain_results': chain_report,
    'registered_decoders': all_decoder_names,
}, indent=2, ensure_ascii=False))
