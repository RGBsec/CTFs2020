import time

from pwn import remote
from utils.factors import find_factors

r = remote("nc challenges.tamuctf.com", 8573)
r.recvuntil("Press enter when you are ready.")
r.recvline()
r.sendline()

while True:
    # try:
    num = r.recvline().strip()
    print(num)
    while num.decode().isnumeric() is False:
        num = r.recvline()
    num = int(num)
    print("Factoring:", num)
    factors = sorted(find_factors(num))
    print("Found:", factors)
    assert len(factors) == 4

    ans = ' '.join([str(f) for f in factors[1:3]])
    print("Sending:", ans)
    r.sendline(ans)

    time.sleep(5)
    # except EOFError:
    #     print(r.recvall(3))