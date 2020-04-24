from PIL import Image
from numpy import ndarray, uint8

arr = ndarray((18, 100, 4), dtype=int)

with open('kuler', 'r') as file:
    row = 0
    col = 0
    for line in file:
        vals = line.strip()[2:]
        if len(vals) == 0:
            row = 0
            col += 1
            continue

        for i in range(3):
            arr[row][col][i] = int(vals[i*2:(i+1)*2], 16)
        arr[row][col][3] = 255
        row += 1

Image.fromarray(arr.astype(uint8)).save("kuler_out.png")