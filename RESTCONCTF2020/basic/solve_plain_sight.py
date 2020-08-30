with open("bum_tam_tam.txt") as f:
    text = f.read()
flag = ''
for c in text:
    if c.isupper():
        flag += c

print(flag)
flag = flag.replace('O', '0').replace('E', '3').replace('A', '4').replace('T', '7')
flag = "RESTCON{" + flag + "}"
print(flag)