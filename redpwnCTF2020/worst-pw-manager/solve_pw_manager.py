from os import chdir, listdir


def recover_pass(filename: str) -> str:
    encrypted = filename.split('_')[1].split('.')[0]
    decrypted = ""
    for shift, c in enumerate(encrypted):
        if c.isalpha() and c.islower():
            value = (ord(c) - ord('a') - shift + 26) % 26
            decrypted += chr(value + ord('a'))
        elif c.isdigit():
            value = (int(c) - shift + 10) % 10
            decrypted += str(value)
        else:
            raise ValueError(c)
    return decrypted


def read_file(filename: str) -> bytes:
    with open(filename, 'rb') as file:
        out = file.read()
    return out


chdir("passwords")
files = sorted(listdir("."), key=lambda s: int(s.split('_')[0]))
print(files)

passes = [recover_pass(file) for file in files]
print(passes)

encrypted = [read_file(file) for file in files]
print(encrypted)


def rc4(text, key):  # from source file
    S = [i for i in range(256)]
    j = 0
    out = bytearray()

    # KSA Phase
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA Phase
    i = j = 0
    for char in text:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(ord(char) ^ S[(S[i] + S[j]) % 256])

    return out


key = [-1] * (len(encrypted) * 8)
for i in range(len(encrypted)):
    for byte in range(32, 256):
        if rc4(passes[i], bytearray([byte] * 8)) == encrypted[i]:
            key[7 + i*8] = byte

print(key)

for L in range(5, 50):
    if L % 8 == 0:
        continue

    flag = ['?'] * L
    for i,k in enumerate(key):
        if k == -1:
            continue
        flag[i % L] = chr(k)

    if '?' not in flag:
        print(''.join(flag))