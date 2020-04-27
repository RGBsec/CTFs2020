import os, sys
from Crypto.Cipher import AES
from Crypto.Util.number import *

file = 'part1_source.png'
content = open(file,'rb').read()

cntr = os.urandom(16)
key=os.urandom(32)
crypto = AES.new(key, AES.MODE_CTR, counter=lambda: cntr) 

encrypted = crypto.encrypt(content)
open(file+'.enc','wb').write(encrypted)


# :phex 0 89 50 4E 47 0D 0A 1A 0A
# :p 40 T
