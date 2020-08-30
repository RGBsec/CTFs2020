import itertools
import string

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

enc = "$argon2id$v=19$m=64,t=16,p=8$Q3liZXJLbmlnaHQwMA$3ZodOqWeWZ0a41c3HQrLY4nawron7LNWajWIyztZkds"

hasher = PasswordHasher(time_cost=16, memory_cost=64, parallelism=8)
for i in range(1, 6):
    print(i)
    for plain in itertools.product(string.ascii_letters, repeat=i):
        try:
            hasher.verify(enc, ''.join(plain))
            print(plain)
        except VerifyMismatchError:
            pass
