from utils.basics import hex_to_ascii
from utils.rsa.rsa_util import plaintext_pn

c = 32949
n = 64741
e = 42667

p = 101

print(plaintext_pn(c, e, p, n))