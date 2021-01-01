from pwn import remote

rem = remote("chall.csivit.com", 30425)
print(rem.recvline().strip().decode())
rem.sendline("NaN")

# why can't you just give us the goddamn flag?
stupid = rem.recvall().decode().split('\n')
stupid = [s for s in stupid if any([c in s for c in "0123456789\""])][1:]

pairs = [(
    int(''.join([c for c in stupid[i] if c.isdigit()])),
    stupid[i + 1].split('"')[1]
) for i in range(0, len(stupid) - 1, 2)]
pairs.sort(key=lambda t: t[0])

flag = ""
for pair in pairs:
    flag += pair[1]
print(flag)