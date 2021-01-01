from PIL import Image
from numpy import ndarray, array, uint8

WIDTH = 300
HEIGHT = 300

dec = ndarray((HEIGHT,WIDTH,3), dtype=uint8)

for r in range(HEIGHT):
    print(r)
    for c in range(WIDTH):
        filename = f"satan_jigsaw/{int.from_bytes(f'{r} {c}'.encode(), 'big')}.jpg"
        # print(filename)

        cur = array(Image.open(filename))
        dec[r][c] = cur[0][0]

Image.fromarray(dec).save("jigsaw_out.png")