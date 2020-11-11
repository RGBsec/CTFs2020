from pwn import remote

PLAIN = 'A' * 32

r = remote("crypto.chal.csaw.io", 5001)
r.recvline()


def get_ans() -> list:
    out = []
    try:
        for i in range(100000):
            print(i)
            x = r.recvline()
            print(x)
            r.sendline(PLAIN)
            print(PLAIN)

            resp = r.recvline().strip()
            print(resp)
            ct = resp.split()[-1]
            y = r.recvline()
            print(y)

            if ct[:32] == ct[32:64]:
                r.sendline("ECB")
                print("ECB")
                out.append("ECB")
            else:
                r.sendline("CBC")
                print("CBC")
                out.append("CBC")
    except Exception as e:
        print('exception:', type(e))
    return out


ans = ['ECB', 'CBC', 'CBC', 'ECB', 'ECB', 'CBC', 'CBC', 'ECB', 'ECB', 'CBC', 'CBC', 'ECB', 'CBC', 'CBC', 'ECB', 'ECB',
       'ECB', 'CBC', 'CBC', 'ECB', 'ECB', 'ECB', 'ECB', 'CBC', 'ECB', 'CBC', 'CBC', 'ECB', 'ECB', 'CBC', 'CBC', 'CBC',
       'ECB', 'CBC', 'CBC', 'CBC', 'CBC', 'ECB', 'CBC', 'CBC', 'ECB', 'CBC', 'ECB', 'ECB', 'ECB', 'CBC', 'ECB', 'CBC',
       'ECB', 'CBC', 'ECB', 'ECB', 'ECB', 'ECB', 'CBC', 'CBC', 'ECB', 'CBC', 'ECB', 'ECB', 'ECB', 'ECB', 'CBC', 'ECB',
       'ECB', 'CBC', 'ECB', 'CBC', 'CBC', 'CBC', 'CBC', 'CBC', 'ECB', 'CBC', 'CBC', 'CBC', 'ECB', 'ECB', 'CBC', 'ECB',
       'ECB', 'CBC', 'CBC', 'ECB', 'ECB', 'CBC', 'ECB', 'CBC', 'ECB', 'CBC', 'ECB', 'ECB', 'ECB', 'ECB', 'ECB', 'ECB',
       'ECB', 'CBC', 'CBC', 'ECB', 'CBC', 'CBC', 'ECB', 'ECB', 'ECB', 'CBC', 'CBC', 'ECB', 'CBC', 'CBC', 'ECB', 'ECB',
       'ECB', 'CBC', 'CBC', 'CBC', 'CBC', 'ECB', 'ECB', 'CBC', 'ECB', 'CBC', 'ECB', 'CBC', 'CBC', 'CBC', 'CBC', 'CBC',
       'ECB', 'CBC', 'CBC', 'CBC', 'ECB', 'ECB', 'CBC', 'CBC', 'ECB', 'CBC', 'ECB', 'CBC', 'ECB', 'CBC', 'ECB', 'CBC',
       'ECB', 'CBC', 'CBC', 'ECB', 'ECB', 'ECB', 'CBC', 'CBC', 'ECB', 'CBC', 'CBC', 'ECB', 'CBC', 'ECB', 'CBC', 'CBC',
       'ECB', 'ECB', 'CBC', 'ECB', 'ECB', 'CBC', 'ECB', 'ECB', 'ECB', 'CBC', 'CBC', 'CBC', 'CBC', 'CBC', 'ECB', 'CBC']
# ans = get_ans()

print(ans)
s = ''.join(ans).replace('ECB', '0').replace('CBC', '1')
print(s)
flag = ""
for i in range(0, len(s), 8):
    flag += chr(int(s[i:i + 8], 2))
print(flag)