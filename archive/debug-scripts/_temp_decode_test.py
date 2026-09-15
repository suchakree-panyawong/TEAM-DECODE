from decoders.base_decoders import decode_base45
from decoders.ciphers import decode_xor_multibyte
from _system_test import encode_base45, encode_xor_multibyte

s = b'Hello World'
en = encode_base45(s)
print('encoded base45:', repr(en))
print('decoded base45:', decode_base45(en))
print('decoded test payload:', decode_base45('8 C VDN44I3E.VDA2'))

text = b'This is a secret message that is long enough for multibyte XOR.'
ct = encode_xor_multibyte(text, b'key')
print('xor payload repr:', repr(ct))
print('xor decoded:', decode_xor_multibyte(ct))
print('xor decoded equals original:', decode_xor_multibyte(ct) == text.decode('utf-8'))
