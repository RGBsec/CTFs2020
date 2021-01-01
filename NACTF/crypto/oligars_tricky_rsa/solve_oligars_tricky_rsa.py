from utils.basics import hex_to_ascii
from utils.rsa.rsa_util import plaintext_pn

c = 97938185189891786003246616098659465874822119719049
e = 65537
n = 196284284267878746604991616360941270430332504451383
p = 10252256693298561414756287  # from factordb

print(hex_to_ascii(plaintext_pn(c, e, p, n)))