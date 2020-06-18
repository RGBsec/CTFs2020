from hashlib import sha256
from itertools import permutations, product

base_words = [b"seed", b"farmer", b"noob", b"plant", b"water", b"soil", b"space", b"air", b"sun"]
words = [[w, w.capitalize(), w.upper()] for w in base_words]
print(words)
for L in range(1, len(words)):
    print(L)
    for s in permutations(words, L):
        for cap in product([0,1,2], repeat=L):
            # plain = b''.join(s)
            plain = b'noob{' + b''.join(w[i] for w,i, in zip(s, cap)) + b'}'
            if "9fe14ff4de4ca35eeb2503a61165d4dff3e6e0714c4ed6ffdfe88df9bae9f0d9" == sha256(plain).digest().hex():
                print(plain)