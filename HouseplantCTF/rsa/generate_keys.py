# Python RSA implementation 10/01/2020
# Key generation
import random
import json
import os
import math
import functools
import numpy as np
import os

YAFU_EXEC = "yafu\\yafu.exe"

def primality_test(n):
    # too slow for big numbers
    # trial division method
    if n <= 3:
        return n > 1
    elif n % 2 == 0 or n % 3 == 0:
        return False

    i = 5

    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6

    return True

def new_primality_test(n, k=128):
    # Miller-Rabin primality test
    # https://medium.com/@prudywsh/how-to-generate-big-prime-numbers-miller-rabin-49e6e6af32fb
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2

    # do k tests
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False
    return True

def prime_candidate(l):
    # get a possible random number
    c = random.getrandbits(l)
    c == c | (1 << l - 1) | 1  # this does something along the lines of making the number odd
    return c

def car_totient(n, k=1):
    # https://codegolf.stackexchange.com/a/93772
    return 1-any(a**-~k*~-a**k%n for a in range(n))or-~f(n,k+1)

def new_car_totient(n):
    # https://github.com/Robert-Campbell-256/Number-Theory-Python/blob/master/numbthy.py
	if n == 1: return 1
	if n <= 0: raise ValueError("*** Error ***:  Input n for carmichael_lambda(n) must be a positive integer.")
	# The gcd of (p**(e-1))*(p-1) for each prime factor p with multiplicity e (exception is p=2).
	def _carmichael_lambda_primepow(theprime,thepow):
		if ((theprime == 2) and (thepow >= 3)):
			return (2**(thepow-2)) # Z_(2**e) is not cyclic for e>=3
		else:
			return (theprime-1)*(theprime**(thepow-1))
	return functools.reduce(lambda accum,x:(accum*x)//gcd(accum,x),tuple(_carmichael_lambda_primepow(*primepow) for primepow in factor(n)),1)

def find_e(n):
    i = 4
    while True:
        if math.gcd(i, n) == 1:
            return i
        else:
            i += 1

def modular_inverse(a, m):
    # https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
    a = a % m;
    for x in range(1, m) :
        if ((a * x) % m == 1) :
            return x
    return 1

# Step 1: Generate primes
if not os.path.exists("primes.json"):
    print("Generating primes")

    primes = []

    for i in range(2):
        print(f"Searching for prime {i+1}")
        while True:
            print("Generating new prime - ", end="")
            p = prime_candidate(1024)
            print(str(p)[:10] + "... - ", end="")
            if new_primality_test(p):
                break
            print("not prime")
        print("prime!")
        primes.append(p)

    primes[0] = int(open("component.txt").read())
    with open("primes.json", "w") as f:
        json.dump({"p": primes[0], "q": primes[1]}, f)
    print("Written to file")
else:
    print("Loading predefined primes")
    with open("primes.json") as f:
        t = json.load(f)
        primes = []
        primes.append(t["p"])
        primes.append(t["q"])

p = primes[0]
q = primes[1]

# Step 2: Find n
print("Generating n")
n = p * q

# Step 3: find Carmichael's totient function of n
print("Finding phi(n)")
#phi_n = new_car_totient(n)
phi_n = np.lcm(p-1, q-1)

# Step 4: find e where e is coprime to phi_n
print("Finding e")
e = find_e(phi_n)

# Step 5: find d where d is d is the modular multiplicative inverse of e % phi_n
print("Finding d")
#d = modular_inverse(e, phi_n)
# because Yafu is fast
d = int(os.popen(f"{YAFU_EXEC} \"modinv({e},{phi_n})\"").read().strip().replace("ans = ", ""))
if os.path.exists("session.log"):  # remove yafu rubbish
    os.remove("session.log")

# Spit out public and priv key
# pub
print("Saving public key")
with open("public-key.json", "w") as f:
    json.dump({"n": n, "e": e}, f)
# priv
print("Saving private key")
with open("private-key.json", "w") as f:
    json.dump({"d": d, "n": n}, f)

print("Done")
