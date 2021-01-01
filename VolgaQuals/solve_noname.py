from base64 import b64decode
from Crypto.Cipher import AES
import time
from hashlib import md5

with open("noname", 'r') as file:
    enc = file.read()

for i in range(int(time.time()), 0, -1):
    key = md5(str(i).encode()).digest()
    aes = AES.new(key, AES.MODE_ECB)
    dec = aes.decrypt(b64decode(enc))
    if b"volga" in dec.lower():
        print(dec)
        break