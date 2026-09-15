from core.engine import auto_decode, decode_once
from core.heuristics import score_text, ngram_fitness, dictionary_confidence_bonus

samples = [
    '3d3d4d5445774d5441774d5445774d5445774d444577',
    'D3%o63616tQA',
    'zrgfmRmR',
    'NWE0YjUy',
]

for s in samples:
    print('INPUT:', s)
    print('SCORE_TEXT(input)=', score_text(s))
    cands = auto_decode(s, max_depth=6, beam_size=80)
    for i, c in enumerate(cands[:10], 1):
        print(i, c.chain, repr(c.text), c.score, 'ng=', ngram_fitness(c.text), 'dic=', dictionary_confidence_bonus(c.text), 'score_text=', score_text(c.text))
    print('-' * 60)

    print('decode_once outputs:')
    for item in decode_once(s, ()):
        print(' ', item)
    print('=' * 80)
