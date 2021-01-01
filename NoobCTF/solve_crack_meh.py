from hashlib import md5
from itertools import permutations

words = [b"Alice", b"January", b"1994", b"USA", b"25", b"Security"]

for L in range(1, len(words)):
    for s in permutations(words, L):
        if "4ee805f9397a1d584ef9be9d2a4f8f20" == md5(b''.join(s)).digest().hex():
            print(b''.join(s))