from collections import Counter

from PIL import Image
import numpy as np

arr = np.array(Image.open("holy_simplicity.png"), dtype=np.uint8)

out = np.empty((*arr.shape, 4), dtype=np.uint8)
for i,row in enumerate(arr):
    for j,cell in enumerate(row):
        for k in range(4):
            shift = 6 - (k*2)
            out[i][j][k] = (cell >> shift) % 16
            out[i][j][k] *= 16
        for k in range(3):
            out[i][j][k] = 0
Image.fromarray(out).save("out.png")