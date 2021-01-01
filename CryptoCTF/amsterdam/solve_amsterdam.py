#!/usr/bin/env python3

from Crypto.Util.number import *
from functools import reduce
import operator

flag = "CCTF{test_flag_yay}"
n = 549
k = 214


def comb(n, k):
    if k > n:
        return 0
    k = min(k, n - k)
    u = reduce(operator.mul, range(n, n - k, -1), 1)
    d = reduce(operator.mul, range(1, k + 1), 1)
    return u // d


def encrypt(msg, n, k):
    msg = bytes_to_long(msg.encode('utf-8'))
    if msg >= comb(n, k):
        return -1
    m = ['1'] + ['0' for i in range(n - 1)]
    for i in range(1, n + 1):
        if msg >= comb(n - i, k):
            m[i - 1] = '1'
            msg -= comb(n - i, k)
            k -= 1
    m = int(''.join(m), 2)
    i, z = 0, [0 for i in range(n - 1)]
    c = 0

    print(m)
    while (m > 0):
        if m % 4 == 1:
            c += 3 ** i
            m -= 1
        elif m % 4 == 3:
            c += 2 * 3 ** i
            m += 1
        m //= 2
        i += 1
    return c


def part2(m):
    c = 0
    i = 0
    while (m > 0):
        if m % 4 == 1:
            c += 3 ** i
            m -= 1
        elif m % 4 == 3:
            c += 2 * 3 ** i
            m += 1
        m //= 2
        i += 1
    return c


def rev_part_2(enc):
    s = ''
    while enc > 0:
        s += str(enc % 3)
        enc //= 3

    return s


# enc = encrypt(flag, n, k)
# print('enc =', enc)
test = part2(234235)
print(bin(test))
rev_part_2(test)

for i in range(1, 50):
    s = rev_part_2(part2(i))
    print(i, part2(i), bin(part2(i)), s)
