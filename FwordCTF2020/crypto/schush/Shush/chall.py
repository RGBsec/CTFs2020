from Crypto.Util.number import getPrime, bytes_to_long
from gmpy2 import gcd
from sympy import nextprime
from secret import flag,BITS

func = lambda x, bits : x**12 + (x & (2**(bits/2)-1))

def PrimeGen(bits):
	pr = getPrime(bits)
	p = nextprime(func(pr,bits))
	qr = getPrime(bits)
	q = nextprime(func(qr,bits))
	return p, q

p,q = PrimeGen(BITS)
n = pow(p,2)*q
c = pow(bytes_to_long(flag),n,n)
