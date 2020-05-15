from string import printable

from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
# from secret import password, flag
from hashlib import sha256

from sympy import ilcm
from sympy.ntheory import reduced_totient, totient

NB_ITERATIONS = 10871177237854734092489348927
e = 65538
N = 16725961734830292192130856503318846470372809633859943564170796604233648911148664645199314305393113642834320744397102098813353759076302959550707448148205851497665038807780166936471173111197092391395808381534728287101705


def derive_key(password):
    start = bytes_to_long(password)

    # Making sure I am safe from offline bruteforce attack

    for i in range(NB_ITERATIONS):
        start = start ** e
        start %= N

    # We are never too cautious let's make it harder

    key = 1
    for i in range(NB_ITERATIONS):
        key = key ** e
        key %= N
        key *= start
        key %= N

    return sha256(long_to_bytes(key)).digest()


def main():
    assert (len(password) == 2)
    assert (password.decode().isprintable())

    key = derive_key(password)
    IV = b"random_and_safe!"
    cipher = AES.new(key, AES.MODE_CBC, IV)
    enc = cipher.encrypt(pad(flag, 16))

    with open("flag.enc", "wb") as output_file:
        output_file.write(enc)


def solve():
    factors = {5: 1, 23: 1, 61: 1, 701: 1,
               3401303653335128045797695889757092041482905417443555040334558532965054282731962107934457608241787496903277518095440908429024366794265591370988690049385889315571999029546461360356028016426404879577552560904181947: 1}
    t = 1
    for p, k in factors.items():
        t *= (p - 1) * p ** (k - 1)
    PHI = 4 * 22 * 60 * 700 * 3401303653335128045797695889757092041482905417443555040334558532965054282731962107934457608241787496903277518095440908429024366794265591370988690049385889315571999029546461360356028016426404879577552560904181946
    print(t)
    print(PHI)
    assert t == PHI

    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def modinv(a, m):
        g, x, y = egcd(a, m)
        if g != 1:
            raise Exception('modular inverse does not exist')
        else:
            return x % m

    def derive_key(password):
        start = bytes_to_long(password)
        secpow = pow(e, NB_ITERATIONS, PHI)
        start = pow(start, secpow, N)
        key = pow(start, ((secpow - 1) * modinv((e - 1), PHI)) % PHI, N)

        return sha256(long_to_bytes(key)).digest()

    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]

    with open("flag.enc", "rb") as input_file:
        enc = input_file.read()

    for c1 in printable:
        for c2 in printable:
            key = derive_key((c1 + c2).encode())
            IV = b"random_and_safe!"
            cipher = AES.new(key, AES.MODE_CBC, IV)
            dec = cipher.decrypt(enc)
            if b'shk' in dec:
                print(dec)
            # flag = dec.decode()
            # if (flag.printable):
            #     print(flag)

solve()