from PIL import Image
import numpy as np
from base64 import b64decode

img1 = np.array(Image.open("image1.png"))
img2 = np.array(Image.open("image2.png"))

img3 = img1 ^ img2
Image.fromarray(img3).save("out.png")

flag = "ZmxhZ3swbjNfdDFtM19QQGQhfQ=="
print(b64decode(flag))