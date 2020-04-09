from pycipher import Playfair
from utils.morseCode import from_morse_code

s = "--- -... -.- --.- .--. - . -.- ... - -.-. -.- ..- .... .-. --.- -.- ...-"
s = from_morse_code(s)
print(s)

letters = "ABCDEFGHIKLMNOPQRSTUVWXYZ"


def gen_full_key(short_key: str) -> str:
    short_key = short_key.upper()
    full_key = ""
    key_letters = set()
    for key_letter in short_key:
        if key_letter not in key_letters:
            full_key += key_letter
            key_letters.add(key_letter)

    for letter in letters:
        if letter not in key_letters:
            full_key += letter
    assert len(full_key) == 25, full_key
    return full_key


while True:
    key = gen_full_key(input("key: "))  # resit
    print(Playfair(key).decipher(s))

# tg = []
# print(s)
# for c1 in letters:
#     for c2 in letters:
#         if c1 == c2: continue
#         for c3 in letters:
#             if c1 == c3 or c2 == c3: continue
#             for c4 in letters:
#                 if c1 == c4 or c2 == c4 or c3 == c4: continue
#                 for c5 in letters:
#                     if c1 == c5 or c2 == c5 or c3 == c5 or c4 == c5: continue
#                     key = gen_full_key(''.join([c1,c2,c3,c4,c5]))
#                     dec = Playfair(key).decipher(s)
#                     if dec.startswith('TGLJ'):
#                         tg.append(dec)
#                     # print(dec, "<==", key)
#
# print(tg)
