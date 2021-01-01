import os
from random import SystemRandom
from Crypto.Util.number import inverse
from gmpy2 import next_prime

class chall:
    def __init__(self, size):
        self.rnd = SystemRandom()
        self.size = size

    def get_key(self):
        p = next_prime(self.rnd.getrandbits(self.size // 2))
        q = next_prime(self.rnd.getrandbits(self.size // 2))
        e = 0x10001

        n = p * q
        phi = (p - 1) * (q - 1)
        
        d_p = inverse(e, p - 1)
        d_q = inverse(e, q - 1)
        inv_q = inverse(q, p)
	
        pubkey = (n, e)
        privkey = (p, q, d_p, d_q, inv_q)

        return (pubkey, privkey)

    def sign(self, msg, privkey):
        p, q, d_p, d_q, inv_q = privkey
        s_p = pow(msg, d_p, p)
        s_q = pow(msg, d_q, q)
        s = s_q + q * ((inv_q * (s_p - s_q)) % p)
        return s

    def verify(self, sgn, pubkey, target):
        n, e = pubkey
        return sgn == pow(target, e, n)

