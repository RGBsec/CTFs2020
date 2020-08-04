from collections import defaultdict
from pwn import remote
from time import sleep

ct = []

# [99126, 76106, 32378, 49560, 87935, 17366, 36639, 33561, 51241, 24009, 82718, 65774, 87030, 53097, 53885, 29931, 10890, 20583, 46190, 99126, 83643]

while True:
    print([list(x.items()) for x in ct])
    r = remote("jh2i.com", 50012)

    cont = False

    r.recvuntil('> ')
    for i, dct in enumerate(ct):
        num = max(dct.items(), key=lambda t: t[1])[0]
        print(num)
        r.sendline(str(num))
        r.recvline()
        resp = r.recvline()
        if b"F A I L" in resp:
            ct[i][int(resp.split()[-1])] += 1
            cont = True
            break
        ct[i][num] += 1
        r.recvline()

    if cont:
        continue

    r.sendline('-1')
    resp = r.recvall().strip()
    print(resp)
    ct.append(defaultdict(lambda: 0))

    try:
        ct[-1][int(resp.split()[-1])] += 1
    except ValueError:
        print(resp)
        break
