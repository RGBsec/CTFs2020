from PIL import Image
import numpy as np


def to_int(arr: list or np.ndarray) -> int:
    return arr[0] * (256 ** 3) + arr[1] * (256 ** 2) + arr[2] * 256 + arr[3]


def from_int(n):
    return [(n // i) % 256 for i in [256 ** 3, 256 ** 2, 256, 1]]


BLACK = to_int([0, 0, 0, 255])
WHITE = to_int([255, 255, 255, 255])
GREEN = to_int([0, 255, 38, 255])
RED = to_int([255, 0, 0, 255])
BLUE = to_int([0, 89, 255, 255])


def simplify(cell):
    colors = set()
    for row in cell:
        for color in row:
            colors.add(to_int(color))

    if BLACK in colors:
        assert WHITE not in colors
        return from_int(BLACK)
    if WHITE in colors:
        assert BLACK not in colors
        return from_int(WHITE)

    for known in [RED, GREEN, BLUE]:
        if known in colors:
            return from_int(known)

    assert False, colors


def add_position_markers():
    img = np.array(Image.open("simplified.png"))
    for r in range(8):
        for c in range(8):
            print(r, c)
            if (r in (1,5) and 0 < c < 6) or (c in (1,5) and 0 < r < 6) or r == 7 or c == 7:
                img[r][c] = from_int(WHITE)
                img[-r - 1][c] = from_int(WHITE)
                img[r][-c - 1] = from_int(WHITE)
            else:
                img[r][c] = from_int(BLACK)
                img[-r - 1][c] = from_int(BLACK)
                img[r][-c - 1] = from_int(BLACK)

    for r in range(8, 17):
        if r % 2 == 0:
            img[r][6] = from_int(BLACK)
        else:
            img[r][6] = from_int(WHITE)

    for i in range(5):
        img[i][8] = img[8][-i - 1]
    for i in range(7,9):
        img[i][8] = img[8][-i]

    img[-8][8] = from_int(BLACK)

    Image.fromarray(img).save("with_markers.png")


def clean_up():
    img = np.array(Image.open("N-95.png"))
    grid = np.array([row[80:-80] for row in img[80:-80]])
    H, W, _ = grid.shape
    out_img = np.zeros((25, 25, 4), dtype=np.uint8)
    for r in range(0, H, 40):
        print(r)
        for c in range(0, W, 40):
            out_img[r // 40][c // 40] = simplify([row[c:c + 40] for row in grid[r:r + 40]])
    Image.fromarray(out_img).save("simplified.png")


def unmask(in_filename, out_filename, mask_func):
    img = np.array(Image.open(in_filename))
    H, W, _ = img.shape
    assert W == 25 and H == 25
    for r in range(H):
        for c in range(W):
            if r == 6 or c == 6:
                continue

            mask_r = r
            mask_c = c
            if r > 6 and c > 6:
                # shift due to timing patterns
                mask_r -= 1
                mask_c -= 1

            if mask_func(mask_r, mask_c) is False:
                if img[r][c].tolist() == from_int(WHITE):
                    img[r][c] = from_int(BLACK)
                elif img[r][c].tolist() == from_int(BLACK):
                    img[r][c] = from_int(WHITE)

    Image.fromarray(img).save(out_filename)


def pixels_to_int(pixels):
    n = 0
    for pixel in pixels:
        n <<= 1
        if pixel.tolist() == from_int(BLACK):
            n += 1
    return n


def decode_25_by_25_qr_code(filename) -> str:
    img = np.array(Image.open(filename))
    encoding = pixels_to_int([img[-2][-2], img[-2][-1], img[-1][-2], img[-1][-1]])

    blocks = [(19, 23, 0), (15, 23, 0),
              (13, 21, 1),
              (15, 21, 2), (19, 21, 2),
              (23, 19, 3),
              (19, 19, 0), (15, 19, 0),
              ]


if __name__ == '__main__':
    # aaa()
    # add_position_markers()
    # unmask("with_markers.png", "jmod3.png", lambda i,j: j%3 == 0)
    decode_25_by_25_qr_code("jmod3.png")