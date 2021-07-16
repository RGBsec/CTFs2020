from numpy import *
from PIL import Image

enc = Image.open(r"wacko.png")
img = array(enc)

key = [41, 37, 23]

a, b, c = img.shape
print(a,b,c)
for x in range(0, a):
    if x % 10 == 0:
        print(x)
    for y in range(0, b):
        pixel = img[x][y]
        for i in range(0, 3):
            tmp = pixel[i]
            while tmp % key[i] != 0:
                tmp += 251
            pixel[i] = tmp // key[i]
        img[x, y] = pixel

flag = Image.fromarray(img)
flag.save("wacko-flag.png")