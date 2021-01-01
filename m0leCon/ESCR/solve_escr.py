from binascii import hexlify
from pwn import remote

def solve_pow(challenge):
    return 'q'

r = remote("challs.ctf.m0lecon.it", 8001)
challenge = r.recvline().decode().strip()
print(challenge)
ans = solve_pow(challenge)
print(ans)
r.sendline(ans)

for _ in range(10):
    hashes = r.recvline().decode().strip()
    s, h = hashes.split(',')
    s = s.strip().strip('(').strip(')').strip('b').strip("'")
    h = h.strip().strip('(').strip(')').strip('b').strip("'")
    print(s, h)

    r.sendline(hexlify(b'\x00' + s.encode()))

print(r.recvall(2).decode())