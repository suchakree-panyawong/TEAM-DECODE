from decoders.ciphers import decode_xor_multibyte
from core.heuristics import score_text

text = b'This is a secret message that is long enough for multibyte XOR.'
ct = bytes(b ^ b'key'[i % 3] for i, b in enumerate(text)).decode('latin-1')
print('ciphertext repr:', repr(ct))
print('decoded:', decode_xor_multibyte(ct))
print('original score:', score_text(text.decode('utf-8')))

# brute-force candidate scoring for keys 1..255 and 'key', 'flag', etc.
from collections import namedtuple
Raw = ct.encode('latin-1')
keys = [[i] for i in range(1, 256)] + [b'key', b'flag', b'ctf', b'1234', b'admin', b'root', b'0x00']
Candidate = namedtuple('Candidate', ['key', 'text', 'score'])
cands=[]
for k in keys:
    dec = bytes(raw[i] ^ k[i % len(k)] for i in range(len(raw)))
    try:
        text_dec = dec.decode('utf-8')
    except UnicodeDecodeError:
        continue
    if text_dec == ct or '\x00' in text_dec: continue
    if any(ord(c) < 32 and c not in '\r\n\t' for c in text_dec): continue
    score = sum(1 for c in text_dec if c.isalnum() or c in ' \n\t{}!@#$%^&*()_+=-')
    cands.append(Candidate(k, text_dec, score))

cands = sorted(cands, key=lambda c: (-c.score, len(c.key)))[:20]
for c in cands:
    print('key', c.key, 'score', c.score, 'text', repr(c.text[:80]))
print('best score meets threshold?', cands[0].score if cands else None, '>', len(raw)*0.85)
