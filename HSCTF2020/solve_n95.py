from PIL import Image
from pyzbar.pyzbar import decode,

code = Image.open("N-95.png")
test = Image.open("qr_code_test.png")
print(decode(code))
print(decode(test))