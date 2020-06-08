from math import gcd
from pwn import remote
from utils.rsa.rsa_util import plaintext_pq
from utils.basics import hex_to_ascii


def get_common_factor_n():
    ciphers = []
    for i in range((2 << 16)):
        r = remote("95.216.233.106", 32394)
        n = int(r.recvline().strip().split()[1])
        e = int(r.recvline().strip().split()[1])
        ct = int(r.recvline().strip().split()[1])

        for cipher in ciphers:
            if gcd(cipher[0], n) != 1:
                return cipher, (n, e, ct)
        ciphers.append((n, e, ct))


def main():
    a, b = get_common_factor_n()

    p = gcd(a[0], b[0])
    assert a[0] % p == 0
    assert p > 1
    q = a[0] // p

    plaintext = plaintext_pq(a[2], a[1], p, q)
    print(plaintext)
    print(hex_to_ascii(plaintext))


if __name__ == '__main__':
    main()