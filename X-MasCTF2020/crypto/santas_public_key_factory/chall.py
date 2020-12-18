import os
from random import SystemRandom
from Crypto.Util.number import inverse
from gmpy2 import next_prime

class chall:
    def __init__(self, size, bits):
        self.rnd = SystemRandom()
        self.bits = bits
        self.size = size
        self.exp = self.rnd.sample(range(32, size - 1), bits)

    def get_rand_int(self):
        res = 2** (self.size - 1)

        for i in range(self.bits):
            if self.rnd.randint(0, 1) == 1:
                res += 2**self.exp[i]

        return res

    def get_prime(self):
        return int(next_prime(self.get_rand_int()))

    def get_key(self):
        p = self.get_prime()
        q = self.get_prime()
        e = 0x10001
        n = p * q
        phi = (p - 1) * (q - 1)
        d = inverse(e, phi)

        pubkey = (n, e)
        privkey = (n, e, d, p, q)

        return (pubkey, privkey)

    def encrypt(self, pt, pubkey):
        n, e = pubkey
        return pow(pt, e, n)

    def decrypt(self, ct, privkey):
        n, e, d, p, q = privkey
        return pow(ct, d, n)
