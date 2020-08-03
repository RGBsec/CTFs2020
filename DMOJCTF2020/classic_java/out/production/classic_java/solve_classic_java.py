def rev3(text) -> str:
    if len(text) == 10:
        raise Exception("hopefully we don't have to deal with this")
    len_lookup = [0, 1, 4, 5, 10, 10, 13, 14, 21, 22, 23]

    orig_len = len_lookup.index(len(text))
    s = [''] * orig_len
    for i in range(orig_len - (orig_len // 5)):
        s[i + (orig_len // 5)] = text[i]
    for i in range(orig_len // 2):
        s[i] = text[i + orig_len - (orig_len // 5)]

    return ''.join(s)

print(rev3("1234010100"))