from math import gcd
from pwn import remote
from utils.basics import hex_to_ascii
from utils.rsa.rsa_util import plaintext_pn

# https://crypto.stackexchange.com/questions/46486/rsa-given-n-e-dp-is-it-possible-to-find-d

r = remote("onepart.fword.wtf", 4445)

r.recvuntil("public pair :")

public_pair = r.recvline().strip().decode().strip('(').strip(')')
n, e = map(int, public_pair.split(','))

assert r.recvline().strip().decode() == "Bonus information"

dp = int(r.recvline().strip().decode().split(':')[1])
c = int(r.recvline().strip().decode().split(':')[1])

print(n)
print(e)
print(dp)
print(c)

r = 8
x = (pow(r, e * dp, n) - r) % n
p = gcd(n, x)
print(p)

assert n % p == 0
assert n > p

print(hex_to_ascii(plaintext_pn(c, e, p, n)))