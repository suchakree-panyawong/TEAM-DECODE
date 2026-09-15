from core.engine import decode_once, _ordered_decoders
payloads = ['54657374', '010000010100001001000011', 'dleihS remmacS rebyC', '3d3d4d5445774d5441774d5445774d5445774d444577']
for p in payloads:
    print('===', p)
    print('priority:', [item['name'] for item in _ordered_decoders(p)[:20]])
    for scheme, decoded in decode_once(p):
        print('->', scheme, repr(decoded))
