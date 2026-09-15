import os, sys, base64, gzip, bz2, lzma, zlib
sys.path.insert(0, os.getcwd())
from core.registry import get_all_decoders
from core.engine import auto_decode
from core.heuristics import rot5, rot18, rot47, atbash
from decoders.base_decoders import decode_base45, decode_base64, decode_base64url, decode_base85, decode_ascii85, decode_z85, decode_base100
from decoders.ciphers import decode_morse, decode_bacon
from decoders.web_decoders import decode_quoted_printable
from decoders.compression import decode_gzip, decode_bzip2, decode_xz, decode_zlib
from decoders.bitwise import decode_xor_singlebyte, decode_xor_multikey
from decoders.ciphers import decode_xor_multibyte

# helper
print('decoders count', len(get_all_decoders()))
print('morse registered', any(d['name']=='morse' for d in get_all_decoders()))

# base45 raw payload
payload = '8 C VDN44I3E.VDA2'
print('base45 payload', payload)
print('base45 decode', decode_base45(payload))

# bacon
payload = 'AAAAA AAAAB'
print('bacon payload', payload, 'decode', decode_bacon(payload))

# quoted printable
payload = 'Hello=20World=21=0A'
print('qp payload', payload, 'decode', decode_quoted_printable(payload))

# xor multibyte
text = b'This is a secret message that is long enough for multibyte XOR.'
key = b'key'
enc = bytes(b ^ key[i % len(key)] for i,b in enumerate(text)).decode('latin-1')
print('xor_multibyte payload repr', repr(enc[:100]))
print('xor_multibyte decode', decode_xor_multibyte(enc))

# auto decode base64 -> morse
payload = base64.b64encode(b'- . ... -').decode()
print('auto payload', payload)
cands = auto_decode(payload, max_depth=4, beam_size=50)
for i, c in enumerate(cands[:10],1):
    print(i, c.chain, c.score, repr(c.text))
print('top text', cands[0].text if cands else None)
