from PIL import Image
import numpy as np

arr = np.array(Image.open("TrafficLightsF.png"), dtype=int)
base = np.array(Image.open("TrafficLightTest.png"), dtype=int)

diff = np.zeros(arr.shape, dtype=int)

H, W, _ = arr.shape

for r in range(H):
    for c in range(W):
        diff[r][c] = base[r][c] - arr[r][c]
        print(diff[r][c], end=' ')
    print()