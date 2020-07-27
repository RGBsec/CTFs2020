from hashlib import sha512
from math import ceil, log2

from sympy import totient

p = 12039102490128509125925019010000012423515617235219127649182470182570195018265927223
q = 1039300813886545966418005631983853921163721828798787466771912919828750891

assert (p - 1) % q == 0

g = 10729072579307052184848302322451332192456229619044181105063011741516558110216720725

x = int.from_bytes(b"Hi! I am Vadim Davydov from ITMO University", 'big')

G = pow(g, x, p)
Gp = int.to_bytes(G, ceil(log2(G) / 8), 'big')

a = sha512(Gp).digest()
ap = int.from_bytes(a, 'big')

t = int(totient(p))
aa = pow(ap, ap, t)

h = aa % p

print("p =", p)
print("q =", q)
print("g =", g)
print("x =", x)
print("G =", G)
print("G'=", Gp)
print("a =", a)
print("a'=", ap)
print("t =", t)
print("aa=", aa)