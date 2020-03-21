from pwn import remote

r = remote("misc.2020.chall.actf.co", 20204)
r.sendline("clamclam")
for i in range(100):
    resp = r.recv_raw(1024)
    print(resp)
    if b"actf" in resp:
        break