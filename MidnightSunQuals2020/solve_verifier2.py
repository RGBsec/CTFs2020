from hashlib import sha3_384
from string import ascii_letters

from pwn import remote
from random import choice
from time import time

r = remote("verifier2-01.play.midnightsunctf.se", 31337)


def server_sign(msg: bytes):
    r.recvuntil('>')

    r.sendline('1')
    r.recvuntil('>')
    print("Sending:", msg)
    r.sendline(msg)
    signature = r.recvline().decode().strip().split(':')[1].strip()
    return signature


for i in range(10):
    s1 = sha3_384(str(int(time())).encode()).hexdigest()
    sig = server_sign(b"The quick brown fox jumps over the lazy dog")
    # s2 = sha3_384(str(int(time())).encode()).hexdigest()
    #
    # print(s1)
    # print(s2)
    print(sig)
    print()