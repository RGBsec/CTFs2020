# from secret import flag
flag = b'asdfgh'
from functools import reduce
from operator import mul
import numpy as np
from Crypto.Util.number import *


def get_magic_modulus(k, nbits=(64, 512)):
    while True:
        e = [int(x) for x in np.random.randint(1, 7, k)]
        print(e)
        p = [getPrime(np.random.randint(nbits[0], nbits[1])) for _ in range(k)]
        exp_list = lambda x, y: pow(x, y)
        n = reduce(mul, list(map(exp_list, p, e)))
        magic = reduce(mul, [
            t - 1 for t in list(map(exp_list, p, [2 * ee + 2 for ee in e]))
        ]) // reduce(mul, [t - 1 for t in list(map(exp_list, p, [2] * k))])
        magic2 = 0
        # for i in range(n+3):
        #     for j in range(i+2,n+3):
        #         magic2 += 1
        # magic2 = (magic2 - 1) * 2
        magic2 = n * (n+3)
        if magic == magic2:
            return n


n = get_magic_modulus(np.random.randint(2, 9))

assert n.bit_length() > 512

e = 65537
c = pow(bytes_to_long(flag), e, n)
print(c)
