import base64
import binascii

c = b'37151032694744553d12220a0f584315517477520e2b3c226b5b1e150f5549120e5540230202360f0d20220a376c0067'


def enc(f):
    e = base64.b64encode(f)
    z = []
    for i in range(len(e)):
        z += [e[i] ^ e[((i + 1) % len(e))]]
    c = binascii.hexlify(bytearray(z))
    return c


def dec(c: bytes):
    z = binascii.unhexlify(c)
    z = list(z)
    print(z)
    for start in range(256):
        res = [start] * len(z)
        for i in reversed(range(1, len(z))):
            res[i] = z[i] ^ res[(i+1) % len(res)]
        try:
            flag = base64.b64decode(bytearray(res))
            if b'flag' in flag:
                return flag
        except binascii.Error:
            pass
    return None


print(dec(c).decode())