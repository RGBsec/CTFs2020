"""
redpwnCTF 2020 Writeups
Challenge: 12 Shades of Redpwn
Category: Crypto
Points: 429

I think this was the worst crypto challenge of redpwnCTF.
We get 2 images of colors. One is a color wheel and the other is the ciphertext.
I didn't want to transcribe the images by hand, so I wrote a PIL script to go through the ciphertext image and get each color.
Then I started guessing different encryptions.
Every two colors were paired in the ciphertext, and the first color was usually in the same general area of the color wheel.
I originally multiplied the first color by 10, and spent a long time rotating and offsetting the color wheel positions.
In the end, the cipher is just the location of the first color, times 12, plus the location of the second color.
Locations start at 0, at the top of the circle.
"""

from PIL import Image
import numpy as np

PACK = 1000


def pack(lst):  # convert a list to a number so that equality can be checked
    ret = 0
    for item in lst:
        ret *= PACK
        ret += item
    return ret


# take the ciphertext image, and extract every 250th pixel so we can work with an image that isn't 980 kb
def compress():
    ct = np.array(Image.open("12-shades.jpg"))
    H, W, _ = ct.shape
    colors = np.array([[ct[750][c] for c in range(250, W, 500)]], dtype=np.uint8)
    Image.fromarray(colors).save("compressed.png")


def main():
    # colors in the color wheel, taken from the color wheel
    # adjusted since the ciphertext colors are slightly different
    color_list = [[255, 255, 000], [255, 204, 0], [255, 101, 1], [255, 51, 0], [254, 0, 0], [152, 0, 101],
                  [153, 0, 153], [103, 0, 153], [0, 0, 254], [0, 152, 153], [0, 153, 0], [0, 255, 1]]
    color_list = [pack(c) for c in color_list]

    # load in the ciphertext
    ct = np.array(Image.open("compressed.png"))[0]
    idxs = []
    for color in ct:
        if pack(color) == pack([255, 255, 255]):  # skip the color if it's white
            continue
        idxs.append(color_list.index(pack(color)))
    out = ''
    for i in range(0, len(idxs), 2):
        val = idxs[i] * 12 + idxs[i + 1]  # calculate the encrypted value
        out += chr(val)
    print(out)


if __name__ == '__main__':
    main()
