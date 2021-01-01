sub = ['v', 'r', 't', 'p', 'w', 'g', 'n', 'c', 'o', 'b', 'a', 'f', 'm',
       'i', 'l', 'u', 'h', 'z', 'd', 'q', 'j', 'y', 'x', 'e', 'k', 's']
rsub = [sub.index(c) for c in sorted(sub)]


def enc2(text):
    temp = ''
    for i in text:
        temp += sub[ord(i) - ord('a')]
    return temp


def rev2(text) -> str:
    temp = ''
    for i in text:
        temp += chr(rsub[ord(i) - ord('a')] + ord('a'))
    return temp


def main():
    key1 = "xtfsyhhlizoiyx"
    key2 = "eudlqgluduggdluqmocgyukhbqkx"
    flag = "lvvrafwgtocdrdzfdqotiwvrcqnd"

    flags = [rev2(flag[i:] + flag[:i]) for i in range(len(flag))]
    key2 = rev2(key2)

    key2 = list(key2)
    key1 = list(key1)
    flags = [list(f) for f in flags]

    for i in range(14):
        a = ord(key2[i + 14])
        key2[i + 14] = a - (ord(key2[i]) - ord('a'))
        if key2[i + 14] < 97:
            key2[i + 14] += 122 - 97
        key2[i + 14] = chr(key2[i + 14])

    key2 = key2[14:]
    print([''.join(f) for f in flags])
    for flag in flags:
        solve(key1.copy(), key2.copy(), flag)
        solve(key2.copy(), key1.copy(), flag)


def solve(key1, key2, flag):
    flag = list(flag)
    for j in range(2):
        for i in reversed(range(14, 28)):
            temp2 = key2[(ord(key1[i - 14]) - ord('a')) % 14]
            key2[(ord(key1[i - 14]) - ord('a')) % 14] = key2[i - 14]
            key2[i - 14] = temp2

            temp1 = flag[(ord(key2[i - 14]) - ord('a')) % 28]
            flag[(ord(key2[i - 14]) - ord('a')) % 28] = flag[i]
            flag[i] = temp1

        for i in reversed(range(14)):
            temp2 = key1[(ord(key2[i]) - ord('a')) % 14]
            key1[(ord(key2[i]) - ord('a')) % 14] = key1[i]
            key1[i] = temp2

            temp1 = flag[(ord(key1[i]) - ord('a')) % 28]
            flag[(ord(key1[i]) - ord('a')) % 28] = flag[i]
            flag[i] = temp1

    key1 = ''.join(key1)
    key2 = ''.join(key2)
    if key1 != rev2(rev2(key2)):
        return
    assert key1 == rev2(rev2(key2)), f"{key1} != {rev2(rev2(key2))}"

    for i in range(len(flag)):
        f = ''.join(flag[i:] + flag[:i])
        if f.startswith("csictf"):
            print(f)


def test():
    key1 = "xtfsyhhlizoiyx"
    key2 = "eudlqgluduggdluqmocgyukhbqkx"
    flag = "lvvrafwgtocdrdzfdqotiwvrcqnd"
    assert key1 == rev2(enc2(key1))
    assert key2 == rev2(enc2(key2))
    assert flag == rev2(enc2(flag))
    print('Tests successful')


if __name__ == "__main__":
    # test()
    main()