import cryptography
from cryptography.fernet import Fernet
import random

class BytesIntEncoder:
    @staticmethod
    def encode(b: bytes) -> int:
        return int.from_bytes(b, byteorder='big')

    @staticmethod
    def decode(i: int) -> bytes:
        return i.to_bytes(((i.bit_length() + 7) // 8), byteorder='big')


file = open('panda_speak/key.key', 'rb')
key = file.read()
file.close()

while True:
    response = input("Paste your message here: ")
    f = Fernet(key)
    encoded0 = f.encrypt(response.encode())
    encoded = str(BytesIntEncoder.encode(encoded0))

    # generate how many splits we want to have
    numofsplits = random.randint(int(len(encoded)/5),int(len(encoded)/2))
    loc = []
    for i in range(0, numofsplits):
        loc.append(random.randint(2, len(encoded)))

    response = ""
    for char in encoded:
        response = response + chr(int(char)+97)

    for inst in loc:
        response = response[:inst] + '|' + response[inst:]

    buffer = response.split("|")
    response = ""
    for segment in buffer:
        noisetype = random.randint(1,5)
        if noisetype == 1:
            segment = "ra" + segment + "wr"
        elif noisetype == 2:
            segment = "gr" + segment + "rr"
        elif noisetype == 3:
            segment = "sq" + segment + "ak"
        elif noisetype == 4:
            segment = "hu" + segment + "ff"
        elif noisetype == 5:
            segment = "ch" + segment + "rp"
        response = response + segment + ' '
    print()
    print(response)
    print()
