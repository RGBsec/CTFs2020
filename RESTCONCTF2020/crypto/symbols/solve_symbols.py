s = '%@$%%#%$$#$f$e_&b_%(#0%%%f$$#!$$%f%$$*#!%#&d'
s = [ord(c) for c in s]

print(s)

for i in range(0, len(s), 2):
    s[i] -= 2
    s[i+1] -= 2
    s[i] %= 15
    s[i+1] %= 15
    print(s[i], s[i+1], chr(s[i] * 16 + s[i+1]), chr(s[i] * 16 + s[i+1] + 5))

print(ord('O'))