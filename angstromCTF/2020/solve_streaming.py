import binascii
import string
from decimal import Decimal

from Crypto.Random import random

a1b4c2 = "01100001011000110111010001100110011110110110010001101111011101110110111001011111011101000110111101011111011101000110100001100101010111110110010001100101011000110110100101101101011000010110110001111101"


def keystream(key):
    e = random.randint(100, 1000)
    while 1:
        d = random.randint(1, 100)
        ret = Decimal('0.' + str(key ** e).split('.')[-1])
        for i in range(d):
            ret *= 2
        yield int((ret // 1) % 2)
        e += 1


a = 1
b = 4
c = 2
key = (Decimal(b * b - 4 * a * c).sqrt() - Decimal(b)) / Decimal(a * 2)
guess = "actf{"
for i in range(64):
    if guess.endswith('}'):
        break
    for c in '{}_' + string.ascii_letters:
        flag = binascii.hexlify((guess+c).encode())
        flag = bin(int(flag, 16))[2:].zfill(len(flag) * 4)
        ret = ""
        k = keystream(key)
        for i in flag:
            ret += str(next(k) ^ int(i))
        if a1b4c2.startswith(ret):
            guess += c
            print(guess)
            break
