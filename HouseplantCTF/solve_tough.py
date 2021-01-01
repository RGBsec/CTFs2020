s = [157, 157, 236, 168, 160, 162, 171, 162, 165, 199, 169, 169, 160, 194, 235, 207, 227, 210, 157, 203, 227, 104, 212, 202]
s = "".join(chr(n) for n in s)
print(s)


for p in range(24):
    if 145 < ord(s[p]) - 10 < 157:
        s = s[:p] + chr(ord(s[p]) - 10) + s[p + 1:]
print(s)

theflags0 = {0: '4', 1: '4', 2: 'y', 3: 't', 4: 'c', 5: '3', 6: 'w', 7: 'h', 8: 'r', 9: '_', 10: '0', 11: '4', 12: '0', 13: '_', 14: 'r', 15: 'h', 16: 'w', 17: '_', 18: '_', 19: '_', 20: 'o', 21: '4', 22: 'u', 23: 'k'}

theflag = ""
for p in range(24):
    theflag += chr(ord(s[p]) - ord(theflags0[p]))

print(theflag)

theflags = {}
theflags1 = {}
for i in range(len(theflag) - 3):
    theflags[i] = theflag[i]

for i in range(len(theflag)-3, len(theflag)):
    theflags1[i] = theflag[i]

print(theflags)
print(theflags1)

realflag = [9, 4, 23, 8, 17, 1, 18, 0, 13, 7, 2, 20, 16, 10, 22, 12, 19, 6, 15, 21, 3, 14, 5, 11]
therealflag = [20, 16, 12, 9, 6, 15, 21, 3, 18, 0, 13, 7, 1, 4, 23, 8, 17, 2, 10, 22, 19, 11, 14, 5]

def uncreate_dict(d: dict, uwu) -> str:
    ret = ['?'] * len(d)
    if uwu:
        for i in range(len(d)):
            try:
                ret[i] = d[realflag[i]]
            except KeyError:
                pass
    else:
        for i in range(len(d)):
            try:
                ret[i] = d[therealflag[i]]
            except KeyError:
                pass
    return ''.join(ret)


print(uncreate_dict(theflags, True))
print(uncreate_dict(theflags1, False))