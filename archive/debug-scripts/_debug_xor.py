from decoders.ciphers import decode_xor_multibyte

plain = b'This is a secret message that is long enough for multibyte XOR.'
ct = bytes(b ^ b'key'[i % 3] for i, b in enumerate(plain)).decode('latin-1')
print('ct repr:', repr(ct))
print('decode_xor_multibyte:', repr(decode_xor_multibyte(ct)))

raw = ct.encode('latin-1')
keys = [[i] for i in range(1, 256)] + [b'key', b'flag', b'ctf', b'1234', b'admin', b'root', b'0x00']

candidates = []
for k in keys:
    dec = bytes(raw[i] ^ k[i % len(k)] for i in range(len(raw)))
    try:
        text = dec.decode('utf-8')
    except UnicodeDecodeError:
        continue
    if text == ct or '\x00' in text:
        continue
    if any(ord(c) < 32 and c not in '\r\n\t' for c in text):
        continue
    score = sum(1 for c in text if c.isalnum() or c in ' \n\t{}!@#$%^&*()_+=-')
    candidates.append((k, score, text))

candidates.sort(key=lambda x: (-x[1], len(x[0]), x[0]))
for k, score, text in candidates[:20]:
    print('key', k, 'score', score, 'text', repr(text[:80]))
for k, score, text in candidates:
    if k == b'key':
        print('found key', k, 'score', score, 'text', repr(text))
        break
print('total candidates', len(candidates))
