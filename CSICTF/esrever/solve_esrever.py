import random
from utils.rotate import rotate


def enc1(text):
    r = random.randint(1, 25)
    return bytes.fromhex(''.join([hex(((ord(i) - ord('a') - r) % 26) + ord('a'))[2:] for i in text])).decode('ascii')


def enc2(text, key):
    k = [key[i % len(key)] for i in range(len(text))]
    return ''.join([chr(ord(text[i]) ^ ord(k[i]) + ord('a')) for i in range(len(text))])


def enc3(text):
    assert len(text) == 42, len(text)
    mapping = [28, 33, 6, 17, 7, 41, 27, 29, 31, 30, 39, 21, 34, 15, 3, 5, 13, 10, 19, 38, 40, 14, 26, 25, 32, 0, 36, 8,
               18, 4, 1, 11, 24, 2, 37, 20, 23, 35, 22, 12, 16, 9]

    temp = [None] * len(text)
    for i in range(len(text)):
        temp[mapping[i]] = text[i]

    return ''.join(temp)


def enc4(text):
    assert len(text) == 31, len(text)
    mapping = [23, 9, 5, 6, 22, 28, 25, 30, 15, 8, 16, 19, 24, 11, 10, 7, 2, 14, 18, 1, 29, 21, 12, 4, 20, 0, 26, 13,
               17, 3, 27]

    temp = [None] * len(text)
    for i in range(len(text)):
        temp[i] = text[mapping[i]]

    return ''.join(temp)


def better_enc1(text):
    r = random.randint(1, 25)
    return ''.join([chr(((ord(i) - ord('a') - r) % 26) + ord('a')) for i in text])


def rev2(text, key) -> str:
    k = [key[i % len(key)] for i in range(len(text))]
    return ''.join([chr(ord(text[i]) ^ ord(k[i]) + ord('a')) for i in range(len(text))])


def rev3(text) -> str:
    assert len(text) == 42, len(text)
    mapping = [28, 33, 6, 17, 7, 41, 27, 29, 31, 30, 39, 21, 34, 15, 3, 5, 13, 10, 19, 38, 40, 14, 26, 25, 32, 0, 36, 8,
               18, 4, 1, 11, 24, 2, 37, 20, 23, 35, 22, 12, 16, 9]

    temp = [None] * len(text)
    for i in range(len(text)):
        temp[i] = text[mapping[i]]

    return ''.join(temp)


def rev4(text) -> str:
    assert len(text) == 31, len(text)
    mapping = [23, 9, 5, 6, 22, 28, 25, 30, 15, 8, 16, 19, 24, 11, 10, 7, 2, 14, 18, 1, 29, 21, 12, 4, 20, 0, 26, 13,
               17, 3, 27]

    temp = [''] * len(text)
    for i in range(len(text)):
        temp[mapping[i]] = text[i]

    return ''.join(temp)


def test():
    s1 = "awehfawhowH(WG#ehgipuJ#R*(@HJTRhweiouh$aeg"
    print(len(s1))
    key = "hfaiuwehgaTJ*)($THWwiuhgruawhgipuwgh"
    print(enc2(s1, key))
    print(enc3(s1))
    assert s1 == rev2(enc2(s1, key), key), rev2(enc2(s1, key), key)
    assert s1 == rev3(enc3(s1))
    assert s1[:31] == rev4(enc4(s1[:31]))

    random.seed(0)
    x = enc1("»·­ª»£µ±¬¥¼±ºµ±¿·£¦­´¯ª¨¥«¥¦«´¸¦¡¸¢²§¤¦¦¹¨")
    random.seed(0)
    y = better_enc1("»·­ª»£µ±¬¥¼±ºµ±¿·£¦­´¯ª¨¥«¥¦«´¸¦¡¸¢²§¤¦¦¹¨")
    assert x == y


def main():
    with open("esrever.txt", 'r') as file:
        enc_key = file.readline().split('=')[1].strip()
        enc_text = file.readline().split('=')[1].strip()
    # print(enc_key)
    # print(enc_text)

    enc_key = rev4(rev4(enc_key))
    keys = rotate(enc_key, start='a')
    # print(keys)

    texts = []
    for key in keys:
        text = rev2(rev3(rev3(enc_text)), key)
        texts.extend(rotate(text, start='a'))

    for flag in texts:
        if "csi" in flag.lower():
            print(flag)


if __name__ == "__main__":
    # test()
    main()