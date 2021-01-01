#!/usr/bin/python3 -u

import random
from Crypto.Util.number import *
import gmpy2

a = 0xe64a5f84e2762be5
print(a)
chunk_size = 64


def gen_prime(bits):
    s = random.getrandbits(chunk_size)

    while True:
        s |= 0xc000000000000001
        p = 0
        for _ in range(bits // chunk_size):
            print(hex(s)[2:], s)
            p = (p << chunk_size) + s
            s = a * s % 2 ** chunk_size
        if gmpy2.is_prime(p):
            print(bin(p))
            return p


n = gen_prime(1024) * gen_prime(1024)
e = 65537
flag = open("flag.txt", "rb").read()
print('n =', hex(n))
print('e =', hex(e))
print('c =', hex(pow(bytes_to_long(flag), e, n)))
