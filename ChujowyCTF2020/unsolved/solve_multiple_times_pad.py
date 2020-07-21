from collections import Counter
from math import log2, ceil
from pwn import remote


def xor(data, key):
    out = []
    for k in range(0, len(data), len(key)):
        block = data[k: k + len(key)]
        out.append(bytes([a ^ b for a, b in zip(block, key)]))
    return b''.join(out)


def try_len(data, key_len):
    ctrs = [Counter([data[i] for i in range(start, len(data), key_len)]) for start in range(key_len)]
    ct = 0
    for ctr in ctrs:
        total = sum(ctr.values())
        cmn = ctr.most_common(1)
        if cmn[0][1] * 12 >= total:
            ct += 1
    return ct


def recover_key(data, key_len) -> bytes:
    ctrs = [Counter([data[i] for i in range(start, len(data), key_len)]) for start in range(key_len)]
    key = bytearray(key_len)
    for i, ctr in enumerate(ctrs):
        cmn = ctr.most_common(1)
        key[i] = cmn[0][0]

    return bytes(key)


def decrypt():
    rem = remote("mtp.chujowyc.tf", 4003)
    num = int(rem.recvall().decode(), 16)
    data = num.to_bytes(ceil(log2(num) / 8), 'big')

    possible = []
    for k in range(128, 256):
        possible.append((k, try_len(data, k)))

    possible.sort(key=lambda t: t[1], reverse=True)
    key_len = possible[0]
    print(key_len)

    key = recover_key(data, key_len[0])
    return xor(data, key)


def part1():
    N = 51839
    ctrs = [Counter() for _ in range(N)]
    for i in range(24):
        dec = decrypt()
        for j, b in enumerate(dec):
            ctrs[j][b] += 1

    final_data = bytearray(N)
    cmns = []
    for i, ctr in enumerate(ctrs):
        cmn = ctr.most_common(5)
        cmns.append(str(cmn))
        final_data[i] = cmn[0][0]

    with open("mtp_debug.txt", "w") as out:
        out.write('\n'.join(cmns))

    with open("mtp_out", 'wb') as out:
        out.write(final_data)


def ngrams(s: bytes, n: int) -> Counter:
    lst = [s[i - n + 1:i + 1] for i in range(n - 1, len(s))]
    return Counter([item for item in lst])


def repeats(s: bytes, n: int = 2) -> Counter:
    lst = [s[i - n + 1:i + 1] for i in range(n - 1, len(s))]
    return Counter([item for item in lst if len(set(item)) == 1])


def quick_analyze(s: bytes, ngram_len = 4):
    for i in range(1, ngram_len+1):
        print(ngrams(s, i).most_common(20))
    print(repeats(s, 2))


def part2():
    with open("mtp_out", 'rb') as f:
        data = f.read()

    quick_analyze(data)
    # data = b''.join(data[i:i+2] for i in range(1, len(data), 3))
    # print(data)

    data = bytearray(data)
    for i in range(len(data)):
        data[i] %= 128
    data = bytes(data)

    data = bytes([d for d in data if 32 <= d < 127]).decode().lower()
    print(data)
    print(Counter(data))

    # parts = [data]
    # seps = [b"\x00", b"\x01", b"\x02", b"\x03", b"\x06", b"\x07", b"\x0a", b"\x0c", b"\x0d"]
    # for sep in seps:
    #     tmp = [p for p in parts if p]
    #     parts = []
    #
    #     for dat in tmp:
    #         parts.extend(dat.split(sep))
    #
    # parts = [p for p in parts if p]
    # s = set()
    # for part in parts:
    #     s.add(part)
    #     if len(part) & 1:
    #         print(part)


if __name__ == '__main__':
    # part1()
    part2()
