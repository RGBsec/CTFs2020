import binascii
from base64 import b64decode
from itertools import permutations

with open("chars.txt") as f:
    s = f.read().strip()

print(s)
for p in permutations('01234'):
    # print(p)
    nums = s.replace("&#8203;", p[0]).replace("&lrm;", p[1]).replace("&rlm;", p[2]).replace("&zwnj;", p[3]).replace("&zwj;", p[4])

    x = []
    for i in range(0, len(nums), 7):
        x.append(int(nums[i+4:i+7], 5))

    out = ''.join([chr(c) for c in x])
    if out.isascii() and out.isprintable():
        print(p)
        print(out.encode())
    # try:
    #     print(b64decode(out))
    # except binascii.Error:
    #     pass