from pwn import remote

r = remote("jh2i.com", 50003)
print(r.recvall().strip().replace(b'\r', b''))