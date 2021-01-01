from utils.basics import ords_to_ascii


def rev1(text) -> str:
    ords = [ord(c) for c in text]
    out = [ord(c) for c in text]
    cur = 0
    for i in range(len(text)):
        cur ^= ords[i]
        out[i] = cur
    return ords_to_ascii(out)


def rev2(text) -> str:
    ords = [ord(c) for c in reversed(text)]
    out = [ord(c) for c in reversed(text)]
    cur = 0
    for i in range(len(text)):
        out[i] = ords[i] ^ cur
        cur ^= ords[i]
    return ords_to_ascii(out)


def rev3(text) -> str:
    if len(text) == 10:
        raise Exception("hopefully we don't have to deal with this")
    len_lookup = [0, 1, 4, 5, 10, 10, 13, 14, 21, 22, 23]

    orig_len = len_lookup.index(len(text))
    s = [''] * orig_len
    for i in range(orig_len - (orig_len // 5)):
        s[i + (orig_len // 5)] = text[i]
    for i in range(orig_len // 2):
        assert s[i] == '' or s[i] == text[i + orig_len - (orig_len // 5)]
        s[i] = text[i + orig_len - (orig_len // 5)]

    return ''.join(s)


def main():
    with open("encrypted") as f:
        ords = [chr(int(c)) for c in f.read().split()]

    # input of len 10 for rev3 results in output of len 23
    blocks = [ords[i:i+23] for i in range(0, len(ords), 23)]
    print(blocks)

    blocks = [rev3(block) for block in blocks]
    print(blocks)

    flag = ""
    for block in blocks:
        assert len(block) == 10 or len(block) == 7
        r1 = rev1(block)
        r2 = rev2(block)
        if r1.isprintable():
            flag += r1
            assert not r2.isprintable()
        else:
            assert r2.isprintable()
            flag += r2

    print(flag)

if __name__ == '__main__':
    main()