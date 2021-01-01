#!/usr/bin/python3 -u

import random
import gmpy2

a = 0xe64a5f84e2762be5
chunk_size = 64


def gen_prime(bits):
    s = random.getrandbits(chunk_size)

    while True:
        s |= 0xc000000000000001
        seed = s
        p = 0
        for _ in range(bits // chunk_size):
            p = (p << chunk_size) + s
            s = a * s % 2 ** chunk_size
        if gmpy2.is_prime(p):
            return p, seed


n = 0xab802dca026b18251449baece42ba2162bf1f8f5dda60da5f8baef3e5dd49d155c1701a21c2bd5dfee142fd3a240f429878c8d4402f5c4c7f4bc630c74a4d263db3674669a18c9a7f5018c2f32cb4732acf448c95de86fcd6f312287cebff378125f12458932722ca2f1a891f319ec672da65ea03d0e74e7b601a04435598e2994423362ec605ef5968456970cb367f6b6e55f9d713d82f89aca0b633e7643ddb0ec263dc29f0946cfc28ccbf8e65c2da1b67b18a3fbc8cee3305a25841dfa31990f9aab219c85a2149e51dff2ab7e0989a50d988ca9ccdce34892eb27686fa985f96061620e6902e42bdd00d2768b14a9eb39b3feee51e80273d3d4255f6b19

# with open("primes.txt", 'a') as f:
#     for i in range(1 << 16):
#         if i & 2047 == 0:
#             print(i)
#         prime = gen_prime(1024)
#         f.write(f"{prime[0]} {prime[1]}\n")

mn = (1 << 1024, -1)
mx = (0, -1)
primes = []
with open("primes.txt") as f:
    for prime in f:
        p = int(prime.split()[0]), int(prime.split()[1])
        primes.append(p)

primes.sort(key=lambda t: t[0])
for i in range(1, len(primes)):
    assert primes[i-1][1] < primes[i][1]
print(primes[0][1])
print(primes[-1][1])