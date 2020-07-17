from math import gcd, log2

from pwn import remote, process
from Crypto.Util.number import inverse

# rem = process(["python3", "ratification.py"])
rem = remote("2020.redpwnc.tf", 31752)


def sign(num):
    msg = num.to_bytes(1024, 'big').strip(b'\x00')
    if b'\t' in msg or b'\n' in msg:
        raise ValueError("cant have newline or tab")

    assert len(rem.recvuntil(b"Exit\n")) >= 29
    rem.sendline(b'1')

    print("sending", msg)
    rem.sendline(msg)
    assert rem.recvline().strip().startswith(b"Message: ")
    return int(rem.recvline())


def main():
    p = int(rem.recvline())
    assert rem.recvline().strip() == b''

    # https://crypto.stackexchange.com/questions/65965/determine-rsa-modulus-from-encryption-oracle
    kn = gcd(sign(2) ** 2 - sign(4), sign(4) ** 2 - sign(16))

    print(kn)
    print(kn % p)
    q = kn // p
    print(q)

    for i in range(2, 10000):
        if q % i == 0:
            q //= i

    print(q)
    assert log2(q) < 1024

    n = p * q
    e = 65537

    forge(p, q, e, n)


def forge(p, q, e, n):
    msg_str = b"redpwnCTF is a cybersecurity competition hosted by the redpwn CTF team."
    message = int.from_bytes(msg_str, 'big')
    b = inverse(e, (p - 1) * (q - 1))

    signature = pow(message, b, n)

    rem.sendline(b'2')
    rem.sendline(msg_str)
    rem.sendline(str(signature).encode())

    print(rem.recvall(3).decode())


if __name__ == '__main__':
    main()