from sympy import divisors
from utils.basics import hex_to_ascii
from utils.rsa.rsa_util import plaintext_pq

with open('ciphertext', 'r') as c:
    ctxt = int(c.read().strip())

with open('public_key', 'r') as pub:
    n, e = pub.read().split(':')
    n = int(n)
    e = int(e)

factors = [div for div in divisors(n) if div != 1 and div != n]

for f in factors:
    print(f)

assert factors[0] * factors[1] == n
for cur_e in range(101, 10000, 2):
    try:
        plain = plaintext_pq(ctxt, cur_e, factors[0], factors[1])
    except ValueError:
        continue
    txt = hex_to_ascii(plain)
    print(cur_e)
    if txt.isprintable() or 'UMD' in txt or 'CTF' in txt:
        print(txt)