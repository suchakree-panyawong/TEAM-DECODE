import os, sys, base64
sys.path.insert(0, os.getcwd())
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
payload = base64.b64encode(b'- . ... -').decode()
print(payload)
for candidate in auto_decode(payload, max_depth=4, beam_size=50)[:20]:
    print(candidate.chain, repr(candidate.text), candidate.score)
