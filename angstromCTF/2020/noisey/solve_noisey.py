import numpy as np
from itertools import zip_longest
from random import gauss
from statistics import mean
from utils.morseCode import from_morse_code

morse = "..."
repeats = 1


bin_to_morse = {
    '10': '.',
    '110': '-',
    '000': ' '
}


def closest(s: str) -> str:
    best = 1000
    close = ""
    for b in bin_to_morse.keys():
        diff = 0
        for c1, c2 in zip(s, b):
            if c1 != c2:
                diff += 1
        if best > diff:
            best = diff
            close = b

    return close


def decode(nums1: list, nums2: list) -> int:
    m = mean(nums1 + nums2)
    if m < 0.5:
        return 0
    return 1


def decode_to_morse(bits):
    msg = ""
    cur = ""
    idx = 0
    while idx < len(bits):
        cur += str(bits[idx])
        for b, m in bin_to_morse.items():
            if cur == b:
                msg += m
                cur = ""
                break
        if len(cur) == 3:
            # print("FAIL at idx:", idx)
            # print("Cur:", cur)
            close = closest(cur)
            if len(close) == 2:
                idx -= 1
            msg += bin_to_morse[close]
            cur = ""

        idx += 1
    return msg


def bits_to_ascii(part):
    msg = decode_to_morse(part)
    ret = ""
    for c in msg.split():
        try:
            ret += from_morse_code(c)
        except KeyError:
            ret += '?'
    return ret


def main():
    with open("noisey.txt", 'r') as f:
        nums = f.readlines()
        assert '\n' not in nums

    nums = [float(n) + .5 for n in nums]
    N = len(nums)//2
    bits = []
    for start in range(0, N, 10):
        bits.append(decode(nums[start:start+10], nums[start+N:start+10+N]))
        # bits.append(decode(nums[start:start+10], nums[start:start+10]))

    print(''.join([str(b) for b in bits]))

    p = bits_to_ascii(bits)
    print(p.lower().replace('u', 'y'))
    print(len(p))
    # print('a' + "noisy"*28 + "noise")


if __name__ == "__main__":
    main()
