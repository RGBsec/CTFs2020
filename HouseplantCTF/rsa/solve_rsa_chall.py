from math import log2

from utils.rsa.rsa_util import *

with open("secrets.txt.enc") as file:
    ct = int(file.read(), 16)

print(log2(ct))
print(find_n_root(ct, 5))