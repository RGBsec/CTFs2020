from __future__ import print_function
import random, os, sys, binascii
from Crypto.Util.number import isPrime
from decimal import *

getcontext().prec = 2000


a1b5c5 = "10100010011001110001000010100111001110001111110010111011100111101110010000001011111101001010010101111111000010010000011100110010100010011011100011110100010100111000100011110010100100000011001110001000011101101001111001110001110101011101101101001110101101000111101111011101001110100001000101100000"


def dstream(key, e, p):
    while 1:
        d = random.randint(10, 100)
        ret = Decimal('0.' + str(key ** e).split('.')[-1])
        ret *= pow(2, d)
        yield int((ret // 1) % 2)
        e += p


def keystream(key):
    # random.seed(int(os.environ["seed"]))
    p = random.randint(3, 50)
    while not isPrime(p):
        p = random.randint(3, 50)
    e = random.randint(50, 700)
    while 1:
        d = random.randint(10, 100)
        ret = Decimal('0.' + str(key ** e).split('.')[-1])
        ret *= pow(2, d)
        yield int((ret // 1) % 2)
        e += p


x = 20
def main(a, b, c):
    try:
        # added some more weak key protections
        if b * b < 4 * a * c or [a, b, c].count(0) or Decimal(
                b * b - 4 * a * c).sqrt().to_integral_value() ** 2 == b * b - 4 * a * c or abs(a) > 400 or abs(
                b) > 500 or abs(c) > 500:
            # print("Failed check 1")
            raise Exception()
        key = (Decimal(b * b - 4 * a * c).sqrt() - Decimal(b)) / Decimal(a * 2)
        if 4 * key * key < 5 or abs(key - key.to_integral_value()) < 0.05:
            # print("Failed check 2")
            raise Exception()
    except:
        # print("bad key")
        return False
    else:
        flag = binascii.hexlify(b"actf{")
        flag = bin(int(flag, 16))[2:].zfill(len(flag) * 4)
        ret = ""
        # print(key)
        # for p in range(51):
        #     if not isPrime(p):
        #         continue
        #     print(p)
        #     for e in range(50, 701):
        #         # print(e, p)
        #         k = dstream(key, e, p)
        #         for i in flag:
        #             ret += str(next(k) ^ int(i))
        #
        #         if a1b5c5.startswith(ret):
        #             print(e, p)
        global x
        if abs(abs(key)-1) < x:
            print(a, b, c)
            x = abs(abs(key)-1)
            print(key)

    return True


if __name__ == "__main__":
    a = 1
    for b in range(500):
        for c in range(500):
            if main(a, b, c):
                pass
    #             # print(a,b,c)
    main(1,36,39)