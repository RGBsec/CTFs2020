from chall import *
from PoW import *
from text import *
import os
from binascii import *

def is_hex(s):
    for c in s:
        if not c in "0123456789abcdef":
            return False
    return True

def collision(h1, h2):
    return h1.string != h2.string and h1.digest() == h2.digest()

if not PoW(5):
    exit()

action_cnt = 2
seed = os.urandom(16)

print (intro.format(action_cnt))

for i in range(action_cnt):
    print (menu)
    x = input()

    if not x in ["1", "2", "3"]:
        print(invalid_input)
        exit()

    if x == "1":
        print (hash_message)
        print (get_msg)
        msg = input()

        if not is_hex(msg):
            print (bad_input)
            exit()

        h = Hash(seed)
        h.update(unhexlify(msg))

        print (show_hash.format(h.hexdigest()))

    if x == "2":
        print (collision_message)

        print (get_msg)
        msg1 = input()
        
        print (get_msg)
        msg2 = input()

        if not (is_hex(msg1) and is_hex(msg2)):
            print (bad_input)
            exit()

        h1 = Hash(seed)
        h2 = Hash(seed)

        h1.update(unhexlify(msg1))
        h2.update(unhexlify(msg2))

        if (collision(h1, h2)):
            print (win.format(FLAG))
        else:
            print (lose)
            exit()
    
    if x == "3":
        print (goodbye)
        exit()
