from Crypto.Util.number import bytes_to_long, getStrongPrime
from fractions import gcd
from secret import flag
from Crypto.Random import get_random_bytes


def encrypt(number):
    return pow(number, e, N)


def noisy_encrypt(a, m):
    return encrypt(pow(a, 3, N) + (m << 24))


e = 3
p = getStrongPrime(512)
q = getStrongPrime(512)

while (gcd(e, (p - 1) * (q - 1)) != 1):
    p = getStrongPrime(512)
    q = getStrongPrime(512)

N = p * q

print("N : " + str(N) + "\n")
print("e : " + str(e) + "\n")

rand = bytes_to_long(get_random_bytes(64))

ct = []
ct.append(encrypt(rand << 24))

for car in flag:
    ct.append(noisy_encrypt(car, rand))

print(ct)
