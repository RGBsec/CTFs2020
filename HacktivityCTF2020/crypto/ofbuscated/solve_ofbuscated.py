# from pwn import remote
# ct = set()
# while len(ct) < 100:
#     r = remote("jh2i.com", 50028)
#     ct.add(r.recvline().strip().decode())
#     print(ct)
from binascii import unhexlify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


ct = ['f24f00b65180b6161b2b9da92d2e42ae652fb2a6ae6732fb47eb3870203ceb4936e1038e327cc16888b6e756f48dd0b8', 'fb1f66cd01ffcc75787bfbd27d4d22cd652fb2a6ae6732fb47eb3870203ceb493fb165f56203bb0bebe6812da4eeb0db', 'e92c6ede25edd6694b4de6f9565624d27e4cdcceda0a5284178d43205b448d3536e1038e327cc16888b6e756f48dd0b8', 'fb1f66cd01ffcc75787bfbd27d4d22cd7e4cdcceda0a5284178d43205b448d3524d20b9d166edb74bb80fa7ddf96d6a7', 'f24f00b65180b6161b2b9da92d2e42ae771cbab58a7528e774dd255b0b27ed5624d20b9d166edb74bb80fa7ddf96d6a7', 'e92c6ede25edd6694b4de6f9565624d2771cbab58a7528e774dd255b0b27ed563fb165f56203bb0bebe6812da4eeb0db']
ct = [unhexlify(c) for c in ct]

for c in ct:
    print(c)
crib = pad(b'}', 16) * 3
print(crib)

keys = [[] for _ in range(0, len(ct[0]), 16)]

for c in ct:
    blocks = [c[i:i+16] for i in range(0, len(c), 16)]
    for x, block in enumerate(blocks):
        cur = byte_xor(block, crib)
        keys[x].append(cur)

pieces = []

for c in ct:
    blocks = [c[i:i+16] for i in range(0, len(c), 16)]
    for x, block in enumerate(blocks):
        for key in keys[x]:
            pieces.append(byte_xor(key, block))

pieces = [piece for piece in set(pieces) if piece.isascii() and piece.decode().isprintable()]
print(pieces)
print(pieces[0] + pieces[1] + b'}')