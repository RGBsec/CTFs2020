from random import choice, randint
from string import ascii_letters, digits
from itertools import cycle


with open("flag.enc", "r") as file:
    enc = file.read()


def valid(dec: str) -> bool:
    return len(set(dec) - set(ascii_letters + digits + '_{}')) == 0


def rec(cur):
    if len(cur) > 16:
        return
    if len(cur) >= 8:
        key_gen = cycle(cur)
        data = []
        for i in range(len(enc)):
            k = next(key_gen)
            data.append(chr(ord(enc[i]) ^ ord(k)))

        dec = ''.join(data)
        if valid(dec):
            print(dec)

    for c in ascii_letters:
        rec(cur + c)


key = "JtmZzCJ"
rec(key)

# hexCTF{supercalifragilisticexpialidocious}