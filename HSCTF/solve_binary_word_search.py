from collections import deque
from PIL import Image
import numpy as np

CHAR_BITS = 8
PRINT_LEN = 10
img = np.array(Image.open("BinaryWordSearch.png"))
grid = [[int(cell[0] == 255) for cell in row] for row in img]


def to_char(bits: deque) -> str:
    n = 0
    for bit in reversed(bits):
        n <<= 1
        n += bit
    return chr(n)


for i in range(len(grid)):
    s = '\n----------\n'
    cur = deque(maxlen=CHAR_BITS)
    for j in range(len(grid[i])):
        ch = to_char(cur)
        if ch.isascii():
            s += ch
        else:
            if len(s) >= PRINT_LEN:
                print(s, end='')
            s = '\n'
    if len(s) >= 8:
        print(s)


for i in range(len(grid)):
    s = '\n----------\n'
    cur = deque(maxlen=CHAR_BITS)
    for j in range(len(grid[i])):
        cur.append(grid[j][i])  # if len > 8, leftmost elem will be automatically popped
        ch = to_char(cur)
        if ch.isascii():
            s += ch
        else:
            if len(s) >= PRINT_LEN:
                print(s, end='')
            s = '\n'
    if len(s) >= 8:
        print(s)



