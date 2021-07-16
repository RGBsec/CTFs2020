from __future__ import print_function
import random, os, sys, binascii
from Crypto.Util.number import isPrime
from decimal import *

try:
    input = raw_input
except:
    pass
getcontext().prec = 2000


def keystream(key):
    random.seed(int(os.environ["seed"]))
    p = random.randint(3, 50)
    while not isPrime(p):
        p = random.randint(3, 50)
    e = random.randint(50, 700)
    while 1:
        d = random.randint(10, 100)
        ret = Decimal('0.' + str(key ** e).split('.')[-1])
        for i in range(d):
            ret *= 2
        yield int((ret // 1) % 2)
        e += p


def main(a, b, c):
    try:
        # added some more weak key protections
        if b * b < 4 * a * c or [a, b, c].count(0) or Decimal(
                b * b - 4 * a * c).sqrt().to_integral_value() ** 2 == b * b - 4 * a * c or abs(a) > 400 or abs(
                b) > 500 or abs(c) > 500:
            print("Failed check 1")
            raise Exception()
        key = (Decimal(b * b - 4 * a * c).sqrt() - Decimal(b)) / Decimal(a * 2)
        print(key)
        print(4 * key * key)
        print(abs(key - key.to_integral_value()))
        if 4 * key * key < 5 or abs(key - key.to_integral_value()) < 0.05:
            print("Failed check 2")
            raise Exception()
    except:
        # print("bad key")
        return False
    else:
        flag = binascii.hexlify(os.environ["flag"].encode())
        flag = bin(int(flag, 16))[2:].zfill(len(flag) * 4)
        ret = ""
        k = keystream(key)
        for i in flag:
            ret += str(next(k) ^ int(i))
        print(ret)

    return True


if __name__ == "__main__":
    # a = 1
    # for b in range(20):
    #     for c in range(20):
    #         if main(a, b, c):
    #             print(a,b,c)
    main(1,5,5)