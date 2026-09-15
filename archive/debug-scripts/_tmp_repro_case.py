import os, sys
sys.path.insert(0, os.getcwd())
from core.engine import auto_decode
from core.heuristics import _score_breakdown, score_text

payloads = [
    'Nz0yOExIRTRFRVw1NEA1Nlw+MkRFNkNcYV9hZE4',
    'Nz0yOExIRTRFRVw1NEA1Nlw+MkRFNkNcYV9hZE4=',
    '7=28LHE4EE\\54@56>2DE6C\\a_adN'
]

for p in payloads:
    print('\n=== PAYLOAD:', p)
    try:
        cands = auto_decode(p, max_depth=4, beam_size=80)
    except Exception as e:
        print('auto_decode error', e)
        continue
    for i,c in enumerate(cands[:8],1):
        print(i, 'chain=', c.chain, 'text=', repr(c.text), 'score=', round(c.score,3))
        bd = _score_breakdown(c.text)
        print('   breakdown:', bd)
    if not cands:
        print(' No candidates')

print('\nDone')
