import base64
from core.engine import auto_decode
from core.heuristics import _score_breakdown

payload = base64.b64encode(b'- . ... -').decode()
print('payload', payload)
cands = auto_decode(payload, max_depth=4, beam_size=50)
for i, c in enumerate(cands[:10], 1):
    print('rank', i)
    print('chain', c.chain)
    print('score', c.score)
    print('text', repr(c.text))
    print('breakdown', _score_breakdown(c.text))
    print('---')
