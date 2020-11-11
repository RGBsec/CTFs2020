from pwn import remote
from random import randint, seed
from time import time

t = time()
print(t)
r = remote("challenges.ctfd.io", 30264)

r.sendline('r')
r.recvuntil('> ')
oracle = int(r.recvline().decode())
print(oracle)

cur = t - 10
while cur < t + 10:
    cur += 0.001
    # print(cur)
    # print(round(cur / 100, 5))
    seed(round(cur / 100, 5))
    if randint(1, 100000000) == oracle:
        print(cur)
        r.sendline('g')
        r.sendline(str(randint(1, 100000000)))
        r.sendline(str(randint(1, 100000000)))
        print(r.recvall().decode())
        break
