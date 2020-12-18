import os
import sys
from hashlib import sha256
from text import *
from chall import *
from PoW import *
import binascii

if not PoW(5):
    exit()

action_cnt = 256
secret_message = os.urandom(8).hex()
cipher = chall(1024, 16)

print(intro.format(action_cnt))

for i in range(action_cnt):
    print(menu)
    x = input()
    if not x in ["1", "2", "3"]:
        print(invalid_input)
        exit()

    if x == "1":
        msg = int(secret_message, 16)
        pubkey, privkey = cipher.get_key()
        ct = hex(cipher.encrypt(msg, pubkey))[2:]
        n, e = pubkey

        print(enc_flag.format(ct, n, e))

    elif x == "2":
        print(guess_msg)
        guess = input()
        if guess == secret_message:
            print(win.format(FLAG))
            exit()
        else:
            print(bad_input)
            exit()

    else:
        print(goodbye)
        exit()

sys.stdout.flush()
