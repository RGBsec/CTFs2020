import random
import hashlib
import sys

p = ''.join(random.choice('0123456789abcdef') for i in range(6))
print("Give me a string such that its sha256sum ends in {}.".format(p))
l = input().strip()
if hashlib.sha256(l.encode('ascii')).hexdigest()[-6:] != p:
    print("Wrong PoW")
    sys.exit(1)


from secrets import flag1, flag2, lim1, lim2
import binascii
import string
import signal
import numpy

def blocks(s):
    ret = []
    for block in range(0, len(s), 32):
        ret.append(bin(int(s[block:block + 32], 16))[2:].rjust(128, '0'))
    return ret

def idxs(s):
    b = blocks(s)
    return [[i for i,bit in enumerate(block) if bit == '1'] for block in b]


def idx(s):
    return [i for i, bit in enumerate(s) if bit == '1']


letters = string.ascii_lowercase+string.ascii_uppercase
secret = numpy.random.permutation(128)
chall = ''.join(random.choice(letters) for _ in range(96))
print(secret.tolist())
print(chall)

def pad(s):
    m = 192 - len(s)
    return s + hex(m%16)[2:]*m

def apply_secret(c):
    r = bin(c)[2:].rjust(128,'0')
    return int(''.join([str(r[i]) for i in secret]), 2)

def encrypt(s):
    # print("encrypting:", s)
    s = pad(s)
    # print("padded:", s)
    to_encrypt = int(s, 16)
    # print("to_encrypt:", hex(to_encrypt))
    for _ in range(9):
        # print("shifted >> 640:", bin(to_encrypt >> 640)[2:].rjust(128, '0'))
        x = apply_secret(to_encrypt >> 640)
        # print("x:   ", bin(x)[2:].rjust(128, '0'))
        # print("x:", idx(bin(x)[2:].rjust(128, '0')))
        # print("enc1:", idx(bin(((x^to_encrypt) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF))[2:].rjust(128, '0')))
        # print("enc2:", idx(bin(to_encrypt >> 128)[2:].rjust(128, '0')))
        to_encrypt = (((x^to_encrypt) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) << 640) | (to_encrypt >> 128)
        # print("to_encrypt:")
        # te = hex(to_encrypt)[2:].rjust(192, '0')
        # print('\n'.join(blocks(te)))
        # print(idxs(te))
        # print()
    return hex(to_encrypt)[2:]

print("Encrypted challenge (hex):")
print(encrypt(binascii.hexlify(chall.encode()).decode()))
req = 0

print(encrypt('0'*191 + '1'))

for _ in range(1024):
    print("What do you want to do?")
    print("1. Encrypt something")
    print("2. Give me the decrypted challenge")
    ans = int(input())
    if ans == 1:
        print("Give me something to encrypt (hex):")
        s = input()
        if len(s) > 192 or not all(c in string.hexdigits for c in s):
            print("Nope1.")
            break
        print(encrypt(s))
        req = req + 1
    elif ans == 2:
        print("Give me the decrypted challenge:")
        c = input().strip()
        if c == chall:
            print("Good job! You did it in {} requests".format(req))
            if req <= lim1:
                print("Level 1 completed: {}".format(flag1))
                if req <= lim2:
                    print("Level 2 completed: {}".format(flag2))
                else:
                    print("Unfortunately, that's not enough for the second flag")
            else:
                print("Unfortunately, that's not enough for the first flag")

        else:
            print("Nope.")
        break
