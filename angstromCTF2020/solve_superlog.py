from Crypto.Util.number import isPrime
from pwn import remote
from sympy.ntheory import reduced_totient
from time import sleep


def rec(a, b, m):
    if b == 0:
        return 1
    else:
        return pow(a, rec(a, b-1, reduced_totient(m)), m)


def parse_line() -> int:
    resp = r.recvline().decode()
    print(resp)
    return int(resp.split('=')[1].strip())


def solve() -> bool:
    r.recvuntil('...\n')
    mod = parse_line()
    a = parse_line() % mod
    b = parse_line() % mod
    assert isPrime(mod)

    print("MOD:", mod)
    print("A  :", a)
    print("B  :", b)

    for x in range(1, 20):
        if b == rec(a, x, mod):
            print("Sending guess:", x)
            r.sendline(str(x))
            return True

    print("Sending bad guess: 8")
    r.sendline(str(8))
    resp = r.recvline()
    if b'Correct' in resp:
        print("Bad guess was correct")
        return True
    return False


if __name__ == "__main__":
    r = remote("3.234.224.95", 20603)

    i = 1
    while i <= 10:
        print('*'*20, f"Solving Challenge #{i}", '*'*20)
        if not solve():
            r.close()
            i = 0
            print('\n\n', '*'*25, "Restarted", '*'*25, '\n\n')
            r = remote("3.234.224.95", 20603)
            sleep(0.1)

        i += 1

    print(r.recvall())
