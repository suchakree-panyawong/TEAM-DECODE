from core.engine import auto_decode

for payload in ['010000010100001001000011','dleihS remmacS rebyC']:
    print('payload:',payload)
    cands = auto_decode(payload, max_depth=4, beam_size=50)
    for i,c in enumerate(cands[:8]):
        print(i, repr(c.text), c.chain, c.score)
    print('---')
