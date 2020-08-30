from hashlib import md5, sha1, sha224, sha256, sha384, sha512

from Crypto.Util.number import isPrime
from pwn import remote
from sympy import nextprime, mod_inverse
from utils.hashes.brute import brute_hash_tail


def solve_challenge(challenge: str):
    if "md5" in challenge:
        func = md5
    elif "sha1" in challenge:
        func = sha1
    elif "sha224" in challenge:
        func = sha224
    elif "sha256" in challenge:
        func = sha256
    elif "sha384" in challenge:
        func = sha384
    elif "sha512" in challenge:
        func = sha512
    else:
        raise ValueError(f"hash function not found in: {challenge}")

    words = challenge.split()
    tail = words[-5]
    length = int(words[-1])
    assert len(tail) == 6
    return brute_hash_tail(func, tail, length)


def query(m: int):
    r.recvuntil(b"[Q]uit\n")
    r.sendline('T')
    r.recvline()
    r.sendline(str(m))
    return int(r.recvline().strip().decode().split()[-1])


def encrypt(m, a, b):
    return m ** 3 + a * m + b


def decrypt(ct, a, b, p):
    print()


r = remote("05.cr.yp.toc.tf", 33371)


def main():
    challenge = r.recvline().strip().decode()
    print(challenge)
    ans = solve_challenge(challenge)
    print(ans)
    r.sendline(ans)
    r.interactive()

    r.recvuntil(b"[Q]uit\n")
    r.sendline('C')
    flag_enc = int(r.recvline().strip().decode().split()[-1])

    b = query(0)
    a = query(1) - b - 1

    print(flag_enc, a, b)

    for i in range(1000000):
        enc = encrypt(i, a, b)
        q = query(i)
        if enc != q:
            if enc < 0:
                p = q - enc
            else:
                p = enc - q

            # just in case some small factors got in
            while p % 2 == 0:
                p >>= 1
            if p % 3 == 0:
                p //= 3

            assert isPrime(p), p

            print("ct =", flag_enc)
            print("a  =", a)
            print("b  =", b)
            print("p  =", p)

            print(decrypt(flag_enc, a, b, p))

            return



if __name__ == '__main__':
    main()
