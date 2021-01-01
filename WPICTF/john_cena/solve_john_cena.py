from collections import Counter

from numpy import array, array_equal
from PIL import Image
from string import ascii_uppercase

digits = '1234567890'

alphabet = {}
for c in ascii_uppercase + digits + '# ':
    try:
        key = c
        if c in digits:
            key = chr(ord('A') + ((int(c) + 9) % 10))
        alphabet[key] = array(Image.open(f"john_cena/alphabet/{c.strip()}.png"))

    except FileNotFoundError:
        pass

print(len(alphabet))
braille = Image.open("john_cena/braille.png")
img = array(braille)

print(img.shape)

height, width, _ = img.shape
W = 30
H = 44
cth = 0
ctw = 0

res = ""

h = 2
while h < height:
    ctw = 0
    for w in range(12, width, W):
        dot = array([arr[w:w+21] for arr in img[h:h+36]])
        for k,v in alphabet.items():
            if array_equal(dot, v):
                res += k
                break
        else:
            print(dot.shape, cth, ctw, h, w)
            Image.fromarray(dot).save(f"john_cena/dots/dot[{ctw}][{cth}].png")

        ctw += 1
    h += H - (cth % 2)
    cth += 1
    # res += '\n'

print(res)

for letter, digit in zip(ascii_uppercase, digits):
    res = res.replace(f'#{letter}', digit)

print(res)
res = res.strip()

with open('john_cena/out', 'wb') as out_file:
    b = bytearray()
    for i in range(0, len(res), 2):
        b.append(int(res[i:i+2], 16))

    out_file.write(b)