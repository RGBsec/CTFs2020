if __name__ == "__main__":
    e = 0
    n = 0
    ciphertexts = []
    with open("c") as file:
        for i, line in enumerate(file):
            if i == 1:
                e, n = eval(line)
            elif i == 4:
                ciphertexts = eval(line)

    print(e)
    print(n)
    print(ciphertexts)

    flag = ""
    for ciphertext in ciphertexts:
        for ch in range(ord(' '), ord('}') + 1):
            if pow(ch, e, n) == ciphertext:
                flag += chr(ch)
                continue

    print(flag)