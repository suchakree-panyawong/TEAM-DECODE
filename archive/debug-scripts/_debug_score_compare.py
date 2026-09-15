from core.heuristics import score_text, _score_breakdown

texts = [
    'TEST',
    '`2ßLÞ_bÒà',
    '- . ... -',
    'Hello World',
    'eHll ooWlrd',
]
for t in texts:
    print('text:', repr(t))
    print('score:', score_text(t))
    print('breakdown:', _score_breakdown(t))
    print('---')
