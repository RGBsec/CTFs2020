import os
import sys
from hashlib import sha256
from binascii import unhexlify

def PoW(size):
    s = os.urandom(10)
    h = sha256(s).hexdigest()
    print ("Provide a hex string X such that sha256(unhexlify(X))[-{}:] = {}\n".format(size, h[-size:]))
    sys.stdout.flush()
    inp = input()
    is_hex = 1
    for c in inp:
        if not c in "0123456789abcdef":
            is_hex = 0
    if is_hex and sha256(unhexlify(inp)).hexdigest()[-size:] == h[-size:]:
        print ("Good, you can continue!")
        sys.stdout.flush()
        return True
    else:
        print ("Oops, your string didn\'t respect the criterion.")
        sys.stdout.flush()
        return False
