from functools import reduce
from itertools import permutations
from operator import xor

SIZE = 15


def decode(enc: str, key: tuple):
    assert len(key) == 4

    blocks = [enc[i:i + SIZE] for i in range(0, len(enc), SIZE)]

    msg = ""
    for block in blocks:
        bits = [int(block[i]) for i in range(len(block))]
        parity = [0] * 4
        for i in reversed(range(4)):
            try:
                parity[i] = bits.pop(key[i])
            except IndexError:
                return "\x00"
        for i in range(4):
            bits.insert(2 ** i - 1, parity[i])

        error = reduce(xor, [i + 1 for i in range(len(bits)) if bits[i]])
        bits[error - 1] = int(not bits[error - 1])
        block_msg = [str(bits[i]) for i in range(len(bits)) if i not in [0, 1, 3, 7]]
        msg += ''.join(block_msg)

    ans = ""
    for i in range(0, len(msg), 8):
        ans += chr(int(msg[i:i + 8], 2))
    return ans


def main():
    with open("enc.txt") as f:
        enc = f.read().strip()

    for key in permutations(range(15), r=4):
        flag = decode(enc, key)
        if flag.isprintable():
            print(flag)


if __name__ == "__main__":
    main()