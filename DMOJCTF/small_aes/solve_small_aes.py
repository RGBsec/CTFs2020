from base64 import urlsafe_b64decode, urlsafe_b64encode
from Crypto.Cipher import AES
from itertools import product

enc = b"53rW_RiyUiwXq3PD7E4RHJuzjlHbw4YmG8wNRILXEQdBFiJZlpI2WjD_kNeQAUYG"
enc = urlsafe_b64decode(enc)

for key in product(range(256), repeat=3):
    key = bytes(key) * 8
    key = urlsafe_b64encode(key)
    cipher = AES.new(key, AES.MODE_ECB)
    if b"ctf" in cipher.decrypt(enc):
        print(cipher.decrypt(enc))