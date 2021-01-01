from Crypto.Util.number import bytes_to_long, long_to_bytes
import random
import string
import binascii
from secret import flag
import signal
import hashlib
import sys

TIME = 30

def handler(signum, frame):
    print('\nToo slow!')
    sys.exit(1)

signal.signal(signal.SIGALRM, handler)

letters = string.ascii_lowercase+string.ascii_uppercase

def rotl(x, n):
    return ((x << n) & 0xffffffffffffffff) | x >> (64 - n)

def rotr(x,n):
    return rotl(x, 64 - n)

class ToyHash(object):
    def __init__(self):
        self.state = [ 0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B,
                       0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B,
                       0x243F6A8885A308D3, 0x13198A2E03707344, 0xA4093822299F31D0]
        self.rounds = 91
        self.mod = 2**64

    def R(self, a, b, c, m1, m2, m3):
        self.state[a] = (self.state[a] + self.state[b] + m1) % self.mod
        self.state[b] = rotl(self.state[b]^self.state[c]^m2,16)
        self.state[c] = (self.state[b] + self.state[c] + m3) % self.mod
        self.state[a] = (self.state[a] + self.state[b] + m1) % self.mod
        self.state[b] = rotr(self.state[b]^self.state[c]^m2,48)
        self.state[c] = (self.state[b] + self.state[c] + m3) % self.mod

    def compress(self, block):
        mini_blocks = [int(block[64*i:64*i+64], 2) for i in range(9)]
        for _ in range(self.rounds):
            self.R(0, 3, 6, mini_blocks[0],mini_blocks[1],mini_blocks[2])
            self.R(1, 4, 7, mini_blocks[3],mini_blocks[4],mini_blocks[5])
            self.R(2, 5, 8, mini_blocks[6],mini_blocks[7],mini_blocks[8])

    def hash(self, m):
        bm = bin(bytes_to_long(m))[2:]
        l = len(bm) % 0x7ff
        bm = bm + '0'*((576-len(bm))%576) + '0'*564 + '1' + bin(l)[2:].rjust(11, '0')
        blocks = [bm[576*i:576*i+576] for i in range(len(bm)//576)]
        for b in blocks:
            self.compress(b)
        h = [self.state[i]^self.state[i+3]^self.state[i+6] for i in range(3)]
        return ''.join(hex(n)[2:].ljust(16, 'f') for n in h).encode()

p = ''.join(random.choice('0123456789abcdef') for i in range(6))
starting_string = ''.join(random.choice(letters) for i in range(10))
print("Give me a string starting in {} such that its sha256sum ends in {}.".format(starting_string,p))
l = input().strip()
if hashlib.sha256(l.encode('ascii')).hexdigest()[-6:] != p or l[:10] != starting_string:
    print("Wrong PoW")
    sys.exit(1)

for _ in range(10):
    s1 = ''.join(random.choice(letters) for i in range(random.randint(50,180))).encode()
    h1 = ToyHash().hash(s1)
    print(str((s1,h1)))
    signal.alarm(TIME)
    s2 = binascii.unhexlify(input())
    h2 = ToyHash().hash(s2)
    signal.alarm(0)
    if s1 == s2 or h1 != h2:
        print("Nope")
        sys.exit(1)

print(flag)
