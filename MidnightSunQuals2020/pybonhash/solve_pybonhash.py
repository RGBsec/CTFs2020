import hashlib, binascii
import string

from Crypto.Cipher import AES

with open("hash.txt", 'r') as file:
    enc = file.readline().strip()

print(enc)

BLOCKS = len(enc) // 64
FIBOFFSET = 4919
MAXFIBSIZE = 42 + BLOCKS*8 + FIBOFFSET


def fibseq(n):
    out = [0, 1]
    for i in range(2, n):
        out += [out[(i - 1)] + out[(i - 2)]]

    return out


FIB = fibseq(MAXFIBSIZE)

data = [-1] * 1000
key = [-1] * 42


def is_hex(s: bytes) -> bool:
    return max(s) <= ord('f') and min(s) >= ord('0')


def f(cur):
    for k1 in range(256):
        for k2 in range(256):
            cipher = AES.new(bytes([k1, k2]) * 16, AES.MODE_ECB)
            dec = cipher.decrypt(cur)
            if is_hex(dec):
                return k1, k2
    return None


def to_str(lst: list):
    return ''.join([chr(c) for c in lst])


def main():
    i = 0
    j = 0
    while i < BLOCKS:
        cur = enc[i * 64:(i + 1) * 64]
        # print(cur)

        cur = binascii.unhexlify(cur)
        ret = f(cur)
        print(ret)

        key[((j + FIB[(FIBOFFSET + j)]) % len(key))] = ret[0]
        j += 1

        key[((j + FIB[(FIBOFFSET + j)]) % len(key))] = ret[1]
        j += 1

        i += 1

    print(key)


if __name__ == "__main__":
    print(to_str([109, 105, 100, 110, 105, 103, 104, 116, 123, 120, 119, 74, 106, 80, 119, 52, 86, 112, 48, 90, 108, 49, 57, 120, 73, 100, 97, 78, 117, 122, 54, 122, 84, 101, 77, 81, 49, 119, 108, 78, 80, 125]))
    # main()
