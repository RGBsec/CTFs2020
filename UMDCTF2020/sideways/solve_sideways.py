from base64 import b64decode, b64encode
from pwn import remote
from paddingoracle import PaddingOracle, BadPaddingException

with open("ciphertext", 'rb') as file:
    ctxt = file.read()

def interact(msg):
    r = remote("192.241.138.174", 1337)
    r.recvuntil("decrypt\n")
    r.sendline(b64encode(msg))
    resp = r.recvline()
    if b"padding" in resp:
        raise BadPaddingException
    print(f"{msg} >> {resp}")



if __name__ == "__main__":
    oracle = PaddingOracle()
    oracle.oracle = interact

    oracle.log.debug = print
    oracle.log.info = print
    oracle.log.exception = print
    print(oracle.decrypt(b64decode(ctxt), block_size=16))

# UMDCTF-{s1d3_ch@nn3l_0p3n}