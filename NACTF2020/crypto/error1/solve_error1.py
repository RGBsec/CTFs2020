from functools import reduce
from operator import xor

with open("enc.txt") as f:
    enc = f.read().strip()

SIZE = 15

blocks = [enc[i:i + SIZE] for i in range(0, len(enc), SIZE)]

msg = ""
print(blocks)
for block in blocks:
    bits = [int(block[i]) for i in range(len(block))]
    error = reduce(xor, [i+1 for i in range(len(bits)) if bits[i]])
    print(error)
    bits[error-1] = int(not bits[error-1])
    block_msg = [str(bits[i]) for i in range(len(bits)) if i not in [0, 1, 3, 7]]
    msg += ''.join(block_msg)

print(msg)
print(len(msg))

ans = ""
for i in range(0, len(msg), 8):
    ans += chr(int(msg[i:i+8], 2))

print(ans)