target = "I$N]=6YiVwC"

num = 1


def pickNum(i: int) -> int:
    global num
    add = (i * (i + 1)) // 2
    num += add

    if num % 2 == 0:
        return num
    else:
        num = pickNum(num)

    return num


target = ''.join(reversed(list(target)))
print(target)

ans = []
for i in range(len(target)):
    num = 1
    pnum = pickNum(i+1) % 127
    ans.append((ord(target[i]) - pnum + 127) % 127)

print(''.join([chr(c) for c in ans]))