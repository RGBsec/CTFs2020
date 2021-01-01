import os
from Crypto.Cipher import AES
from binascii import hexlify

def xor(a, b):
    return bytes([x^y for x,y in zip(a, b)])

def pad(msg, block_size):
    if len(msg) % block_size == 0:
        return msg
    return msg + bytes(block_size - len(msg) % block_size)

class Hash:
    def __init__(self, seed = None):
        if seed == None:
            seed = os.urandom(16)

        self.perm = AES.new(seed, AES.MODE_ECB)
        self.get_elem = self.perm.encrypt
        self.hash = bytes(16)
        self.string = b""

    def update(self, msg):
        msg = pad(msg, 16)
        for i in range(0, len(msg), 16):
            self.string += msg[i:i+16]
            self.hash = xor(msg[i:i+16], self.get_elem(xor(self.hash, msg[i:i+16])))

    def digest(self):
        return self.hash

    def hexdigest(self):
        return hexlify(self.digest())
