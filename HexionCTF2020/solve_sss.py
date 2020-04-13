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

    nums = []  # avoid inexact division
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
    r = remote("challenges1.hexionteam.com", 5001)
    r.recvuntil(">>>")
    shares = []
    for i in range(0x1, 0x50):
        if i == ord('\n'):
            continue
        r.sendline(long_to_bytes(i))
        resp = r.recvline().decode()
        resp = resp.strip().strip('>').strip()
        shares.append((i,int(resp)))
    print(shares)
    print(long_to_bytes(recover_secret(shares)))


if __name__ == '__main__':
    main()
