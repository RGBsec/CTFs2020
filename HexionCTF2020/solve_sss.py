"""
Writeup for Hexion CTF 2020
By Stanley
Challenge: SSS
Category: Crypto
Points: 908 (as of time of writing)
Description:
    Math is so beautiful and can always be used for cryptographic encryption!
    nc challenges1.hexionteam.com 5001
    Author: Yarin

We are given an sss.py. See https://pastebin.com/KQhdB3fa for source.
I found that SSS stands for Shamir's Secret Sharing by copy-pasting the loop from eval_at, which brought me to this Wikipedia page: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing

From there I learned that sss.py was basically giving out shares, with the flag as the secret. So we can just request enough shares until we meet the minimum threshold to be able to recover the secret.

Most of this code (nearly everything except main) is taken from Wikipedia's example implementation of Shamir's Secret Sharing
If you want to understand it, Wikipedia can explain it much better than I can
"""

from Crypto.Util.number import long_to_bytes
from pwn import remote

P = 2 ** 521 - 1


def eval_at(poly, x, prime):
    accum = 0
    for coeff in reversed(poly):
        accum *= x
        accum += coeff
        accum %= prime
    return accum


def extended_gcd(a, b):
    x = 0
    last_x = 1
    y = 1
    last_y = 0
    while b != 0:
        quot = a // b
        a, b = b, a % b
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y
    return last_x, last_y


def divmod(num, den, p):
    inv, _ = extended_gcd(den, p)
    return num * inv


def _lagrange_interpolate(x, x_s, y_s, p):
    k = len(x_s)
    assert k == len(set(x_s)), "points must be distinct"

    def PI(vals):  # product of inputs
        accum = 1
        for v in vals:
            accum *= v
        return accum

    nums = []
    dens = []
    for i in range(k):
        others = list(x_s)
        cur = others.pop(i)
        nums.append(PI(x - o for o in others))
        dens.append(PI(cur - o for o in others))
    den = PI(dens)
    num = sum([divmod(nums[i] * den * y_s[i] % p, dens[i], p)
               for i in range(k)])
    return (divmod(num, den, p) + p) % p


def recover_secret(shares, prime=P):
    x_s, y_s = zip(*shares)
    return _lagrange_interpolate(0, x_s, y_s, prime)


def main():
    # connect to the nc server
    r = remote("challenges1.hexionteam.com", 5001)
    r.recvuntil(">>>")
    shares = []

    # request 78 shares, just to be safe (min is a random int between 48 and 63, inclusive)
    for i in range(0x1, 0x50):
        if i == ord('\n'):  # pwn remote didn't like me sending a newline, so I skipped that one
            continue
        r.sendline(long_to_bytes(i))
        resp = r.recvline().decode()
        resp = resp.strip().strip('>').strip()
        shares.append((i,int(resp)))

        if len(shares) % 5 == 0:
            print("Acquired", len(shares), "shares")

    # print(shares)
    print(long_to_bytes(recover_secret(shares)))


if __name__ == '__main__':
    main()

# hexCTF{d0nt_us3_shar3s_lik3_that}