import binascii
from hashlib import sha256
from itertools import product
from math import log2
from pwn import remote


# solve the Proof-Of-Work
def find_tail(tail: str, tail_len=6):
    for L in range(1, 10):
        for s in product(b"0123456789abcdefghijklmnopqrstuvwxyz", repeat=L):
            if sha256(bytearray(s)).hexdigest()[-tail_len:] == tail:
                return bytearray(s).decode()
    raise ValueError("unable to find solution to POW")


# split a hex string into blocks
def blocks(s):
    ret = []
    for block in range(0, len(s), 32):
        ret.append(bin(int(s[block:block + 32], 16))[2:].rjust(128, '0'))
    return ret


# This apply_secret has the same functionality as the source on the server side
# We don't really need to know how this works - we can abstract it away
# If it matters, it shuffles the bits of a number with a permutation
def apply_secret(c, secret):
    r = bin(c)[2:].rjust(128, '0')
    return int(''.join([str(r[i]) for i in secret]), 2)


# Given the secret, reverse the encryption
# Encrypt splits the number into 6 blocks of 128 bits each
# It runs 9 times
# Each time, it takes the top block, applies the secret, and xors it with the bottom block
# Then each block is shifted down
#   A     B     C     D     E     F
# f(A)^F  A     B     C     D     E
# We known A, B, C, D, and E. Since we have the secret, we also know f(A)
# Then to get F, we can xor the top block with f(A)
# Then shift the blocks back
def decrypt(n: int, secret: list):
    to_decrypt = n
    for _ in range(9):
        top_block = to_decrypt >> 640  # f(A) ^ F
        second_block = (to_decrypt >> 512) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF  # A
        # 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF is 2^128 - 1
        # this is the same as mod 2^128

        to_decrypt = (to_decrypt << 128) % (1 << 768)  # shift the blocks up, and take out the top one
        x = apply_secret(second_block, secret)  # get f(A)
        to_decrypt |= x ^ top_block  # fill in the bottom block with F

    dec = hex(to_decrypt)
    print(dec)
    dec = dec[2:]  # remove "0x"

    # unhexlify only works if its input has an even length
    if len(dec) & 1:
        dec = '0' + dec

    return binascii.unhexlify(dec)


# test decrypt with locally generated examples
def test():
    enc = 0xcb97861c616e58a69126260cf4c64e74f0fa21838edf2f3a047e38a95328823b60b636e2c9502d88623080299f85d4e572464edabb8863389937df66ac2262b4b8fc0bb93c51684e8c0e8fd82ac04f06c15a31fc1d9fc71cac0f2ad15dcf39b9
    secret = [48, 14, 40, 108, 94, 0, 79, 25, 59, 58, 104, 88, 1, 3, 73, 7, 90, 53, 106, 24, 92, 50, 103, 17, 64, 111,
              18, 101, 12, 65, 83, 96, 13, 43, 4, 127, 119, 67, 23, 77, 2, 87, 123, 38, 118, 97, 113, 70, 74, 121, 98,
              16, 71, 60, 41, 22, 33, 80, 102, 100, 39, 116, 10, 115, 49, 27, 125, 124, 76, 109, 8, 37, 112, 84, 63, 31,
              117, 56, 114, 69, 36, 46, 11, 45, 52, 86, 6, 82, 122, 32, 66, 93, 91, 55, 72, 51, 62, 105, 68, 5, 75, 29,
              20, 95, 54, 126, 47, 28, 19, 57, 44, 21, 107, 30, 110, 61, 120, 85, 35, 78, 34, 9, 81, 26, 42, 15, 89, 99]

    print(decrypt(enc, secret))


def main():
    # test()
    r = remote("challs.m0lecon.it", 11000)

    resp = r.recvline().decode().strip()
    tail = resp.split()[-1].strip('.')
    print(resp)

    pow_ans = find_tail(tail)

    r.sendline(pow_ans)
    print(">", pow_ans)

    print(r.recvline().decode().strip())

    chall = r.recvline().decode().strip()
    print(chall)

    secret = [-1 for _ in range(128)]
    for i in range(127):
        print(r.recvuntil("Give me the decrypted challenge\n").decode().strip())
        query = str(hex(1 << i))[2:].rjust(32 * 6, '0')
        r.sendline('1')
        print('> 1')
        print(r.recvuntil("Give me something to encrypt (hex):\n").decode().strip())
        r.sendline(query)
        print('>', query)

        result = r.recvline().decode().strip()
        print(result)
        value = round(log2(int(result[-32:], 16)))
        index = round(log2(int(result[-64:-32], 16)))
        secret[127 - index] = 127 - value

    print("secret:", secret)

    missing = 0
    for i in range(128):
        if i not in secret:
            missing = i
            break
    for i in range(128):
        if secret[i] is -1:
            secret[i] = missing
            break

    dec = decrypt(int(chall, 16), secret)

    r.sendline('2')
    print('> 2')

    print(r.recvuntil("Give me the decrypted challenge:\n").decode().strip())
    r.sendline(dec)
    print('>', dec)

    print(r.recvall(4).decode())


if __name__ == '__main__':
    main()
