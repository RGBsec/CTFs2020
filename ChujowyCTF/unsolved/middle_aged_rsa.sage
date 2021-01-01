from hashlib import sha256
from flag import flag

def encrypt_chunk(N, e, chunk):
    x = int.from_bytes(chunk, 'big')
    y = randint(0, 256^len(chunk))
    return Zmod(N)(x*y)^e

p, q = [random_prime(2^1024) for _ in range(2)]
N = p * q
e = 0x10001
print(N, e)
print(sha256(flag).hexdigest())
print([encrypt_chunk(N, e, flag[i:i+3]) for i in range(0, len(flag), 3)])
