#!/usr/bin/python
from Crypto.Util.number import *
from random import *
from gmpy2 import *
from fractions import * 
from binascii import hexlify
from secret import flag

#Setting up params
a = randrange(2**10,2**11)
b = randrange(2**12,2**13)
c = randint(2,2**1024)

p = next_prime((a * c) + randint(2,2**512))
q = next_prime((b * c) + randint(2,2**512))

n = p * q
e=randint(1024,70000)
while True:
	if ( (e & (e+1) == 0) and gcd(e,(p-1)*(q-1))==1):
		exp=e 
		break
	e+=1

m=int(hexlify(flag.encode()).decode(),16)

enc=pow(m,exp,n)


print ("n : "+str(n))
print ("a : "+str(a))
print ("b : "+str(b))
print ("enc : "+str(enc))

