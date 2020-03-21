from math import sqrt
from random import randint
from utils.z_algorithm import *

from PIL import Image

im = Image.open('breathe.jpg')
im2 = Image.open("output.png")

width, height = im.size
assert im.size == im2.size

flag = "actf{local_fake_flag}"
flag = ''.join([str(ord(i)) for i in flag])
print(flag)


def encode(i, d):
    i = list(str(i))
    i[0] = d

    return int(''.join(i))


def code(a, b):
    if len(str(a)) != len(str(b)):
        return 0
    if b == 255 and (a-b) % 100 != 0:
        # return 1
        return 3

    # return 1
    # return min(3, int(str(b)[0]))
    return int(str(b)[0])


c = 0
s = ""

print(width, height)
for j in range(height):
    for i in range(width):
        data = []
        for a,b in zip(im.getpixel((i, j)), im2.getpixel((i,j))):
            s += str(code(a,b))
        #     data.append(encode(a, flag[c % len(flag)]))

            c += 1

        # im.putpixel((i, j), tuple(data))

# with open("code.txt", 'w') as f:
#     f.write(s + '\n')
# print(len(s))
#
# n = len(s) // 2
#
# ret = search_with_z_algo(s, s[::n])
# while n >= 1 and len(ret) == 1:
#     n -= 1
#     ret = search_with_z_algo(s, s[::n])
#
# end = int(sqrt(n+1))
# ret = search_with_z_algo(s[:n], s[:end])
# while end >= 1 and len(ret) == 1:
#     end -= 1
#     while end >= 2 and n % end != 0:
#         end -= 1
#
#     ret = search_with_z_algo(s[:n], s[:end])
#
# print(n, end)
# ret = search_with_z_algo(s, s[:2516])
# for i in range(len(ret)-1):
#     print(ret[i+1] - ret[i])

N = 2516*4
final = ""
for i in range(N, len(s), N):
    ans = ""
    cur = ""
    for c in s[i-N:i]:
        cur += c
        if (cur[0] != '1' and len(cur) == 2) or (cur[0] == '1' and len(cur) == 3):
            ans += chr(int(cur))
            cur = ""

    # print(ans)

    if len(final) == 0:
        final = ans
    else:
        assert len(final) == len(ans)
        tmp = final
        final = ""
        for i in range(len(ans)):
            if tmp[i] == '}' or ord(tmp[i]) == ord('}') + 10:
                final += '}'
            elif tmp[i] in 'qg!':
                final += ans[i]
            else:
                final += tmp[i]

print(final)
