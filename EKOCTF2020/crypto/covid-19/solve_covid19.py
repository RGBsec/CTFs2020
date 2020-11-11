from utils.basics import hex_to_ascii

with open("covid") as f:
    lines = [line.strip() for line in f]

s = lines[3].split('"')[1]
s = s.replace(')', '')
flag = hex_to_ascii(s)
print(flag)
