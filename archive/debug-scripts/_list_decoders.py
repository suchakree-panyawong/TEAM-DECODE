import os, sys
sys.path.insert(0, os.getcwd())
from core.registry import get_all_decoders
for d in get_all_decoders():
    print(d['name'], d['category'])
