from binascii import unhexlify
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ct = unhexlify("441A65DEFFEFC5A3B3F4A83ED6A9EA463D7782E23D516226A5CFC8477757D46F023A8E39FF4BCE61C6F883B202728978")

cipher = AES.new(b"pony"*4, AES.MODE_CBC, iv=b'\x00'*16)
print(unpad(cipher.decrypt(ct), AES.block_size))