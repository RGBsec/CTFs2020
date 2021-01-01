#!/usr/bin/env python3
import os
import random

def xor(data, key):
    out = []
    for k in range(0, len(data), len(key)):
        block = data[k : k + len(key)]
        out.append(bytes([a ^ b for a, b in zip(block, key)]))
    return b''.join(out)

def randkey():
    return os.urandom(random.randrange(128, 256))

if __name__ == "__main__":
    with open('flag', 'rb') as f:
        data = f.read()
    print(xor(data, randkey()).hex())

# nc mtp.chujowyc.tf 4003
