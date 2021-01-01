from string import ascii_letters


def super_secret_decryption(password: bytes):
    with open("blackmail_encrypted", "rb") as f:
        ciphertext = f.read()
    remove_spice = lambda b: 0xff & ((b >> 1) | (b << 7))
    plaintext = bytearray(remove_spice(c ^ password[i % len(password)]) for i, c in enumerate(ciphertext))

    assert b"Isabelle" in plaintext, password
    flag = plaintext.find(b"uiuctf")
    if flag != -1:
        print(plaintext[flag:flag+50])


def find_key(crib: bytes, enc: bytes) -> bytes:
    assert len(crib) == len(enc)
    remove_spice = lambda b: 0xff & ((b >> 1) | (b << 7))
    key = bytearray()
    for i in range(len(enc)):
        for byte in ascii_letters.encode():
            if remove_spice(enc[i] ^ byte) == crib[i]:
                key.append(byte)
                break

    return bytes(key)


def main():
    with open("blackmail_encrypted", "rb") as f:
        ciphertext = f.read()

    crib = b"Isabelle"
    keys = set()
    for i in range(len(ciphertext)):
        # if i & 2047 == 0:
        #     print(i)
        if i + 8 >= len(ciphertext):
            break
        key = find_key(crib, ciphertext[i:i + 8])
        if len(key) == 8 and key.isalpha():
            rotate = (8 - (i % 8)) % 8
            print(i, i % 8, key, key[rotate:] + key[:rotate])
            keys.add(key[rotate:] + key[:rotate])

    print(keys)
    for key in keys:
        super_secret_decryption(key)


if __name__ == '__main__':
    main()
