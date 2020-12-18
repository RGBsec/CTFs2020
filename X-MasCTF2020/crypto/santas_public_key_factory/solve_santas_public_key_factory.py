from binascii import hexlify
from math import gcd
from pwn import remote
from utils.hashes.finder import get_sha256_tail
from utils.rsa.rsa_util import plaintext_pn


def run():
    r = remote("challs.xmas.htsp.ro", 1000)

    def get_num(base):
        line = r.recvline().decode().strip()
        x = line.split()[-1].strip('.')
        return int(x, base)

    PoW = r.recvline().decode().strip().split()[-1]
    ans = get_sha256_tail(PoW)
    print(PoW, ans)
    r.sendline(hexlify(ans.encode()))

    print(r.recvuntil("exit\n\n").decode().strip())
    nums = []
    for i in range(255):
        print(i)
        r.sendline('1')

        enc = get_num(16)
        r.recvline()
        n = get_num(10)
        e = get_num(10)

        print(n)

        for other in nums:
            g = gcd(n, other)
            if g > 1:
                print("n =", n)
                print("n'=", other)
                p = g
                print("p =", p)
                print("n mod p =", n % p)

                pt = plaintext_pn(enc, e, p, n)
                print("c =", enc)
                print("m =", pt)
                print(hex(pt)[2:])

                r.sendline('2')
                r.sendline(hex(pt)[2:])

                print(r.recvall(3).decode())
                return True

        nums.append(n)

        r.recvuntil("exit\n\n").decode().strip()
    return False


while run() is False:
    pass



# from random import SystemRandom
# from gmpy2 import next_prime
# from sympy import factorint
#
# size = 1024
# bits = 16
# rnd = SystemRandom()
# exp = rnd.sample(range(32, size - 1), bits)
#
# def get_rand_int():
#     res = 2** (size - 1)
#
#     for i in range(bits):
#         if rnd.randint(0, 1) == 1:
#             res += 2**exp[i]
#
#     return res
#
# x = get_rand_int()
# y = get_rand_int()
# c = bin(x * y)[2:]
# p = next_prime(x)
# q = next_prime(y)
# n = bin(p * q)[2:]
#
# print(x * y)
#
# print(len(c), len(n))
#
# bp = bin(p)
# bq = bin(q)
# print(bp)
# print(bq)
# print(c)
# print(n)
# print([i for i in range(len(bp)) if bp[i] == '1'])
# print([i for i in range(len(bq)) if bq[i] == '1'])
# print([i for i in range(len(c)) if c[i] == '1'])
# print([i for i in range(len(n)) if n[i] == '1'])
# print(n.count('1'))
# m = (p * q) & ((1 << 64) - 1)
# factors = factorint(m)
# print(m, factors)
# for k, v in factors.items():
#     print(bin(k))

from math import factorial
total = (2 ** 16) ** 510
bad = factorial(2**16) // factorial(2**16 - 510)
print(total)
print(bad)
print((total - bad) / total)