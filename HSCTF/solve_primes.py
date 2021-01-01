from sympy import nextprime

with open("Primes.txt") as f:
    text = f.read().strip()

i = 0
s = ""

for j in range(10):
    print(i)
    s += text[j*j - j + 1]
    i = nextprime(i)

print(s)