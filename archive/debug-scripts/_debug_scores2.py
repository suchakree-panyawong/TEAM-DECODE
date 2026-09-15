from collections import namedtuple
from decoders.ciphers import decode_xor_multibyte
from _system_test import encode_xor_multibyte

text = b'This is a secret message that is long enough for multibyte XOR.'
ct = encode_xor_multibyte(text, b'key')
print('ciphertext repr', repr(ct))
print('ciphertext len', len(ct))
print('original text', text.decode('utf-8'))
print('decoded from auto decoder:', decode_xor_multibyte(ct))

raw = ct.encode('latin-1')
keys = [[i] for i in range(1, 256)] + [b'key', b'flag', b'ctf', b'1234', b'admin', b'root', b'0x00']
Candidate = namedtuple('Candidate', ['key', 'text', 'score'])
cands = []
for k in keys:
    dec = bytes(raw[i] ^ k[i % len(k)] for i in range(len(raw)))
    try:
        text_dec = dec.decode('utf-8')
    except UnicodeDecodeError:
        continue
    if text_dec == ct or '\x00' in text_dec:
        continue
    if any(ord(c) < 32 and c not in '\r\n\t' for c in text_dec):
        continue
    score = sum(1 for c in text_dec if c.isalnum() or c in ' \n\t{}!@#$%^&*()_+=-')
    cands.append(Candidate(k, text_dec, score))

cands = sorted(cands, key=lambda c: (-c.score, len(c.key), c.key))
for c in cands[:20]:
    print('score', c.score, 'key', c.key, 'text', repr(c.text))
print('best candidate total', len(cands))
for c in cands:
    if c.key == b'key':
        print('found key', c.key, 'score', c.score)
        break
