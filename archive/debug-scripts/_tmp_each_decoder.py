import os,sys
sys.path.insert(0, os.getcwd())
from core.registry import get_all_decoders
s = '7=28LHE4EE\\54@56\\>2DE6C\\a_adN'
print('Input:', s)
for d in get_all_decoders():
    name = d['name']; func = d['func']
    try:
        res = func(s)
    except Exception as e:
        res = f'ERROR: {e!r}'
    if res:
        print(f"{name} -> {res}")
