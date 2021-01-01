from pwn import remote

texts = []

for _ in range(10):
    r = remote("repeat.fword.wtf", 4545)
    for _ in range(5):
        r.recvuntil(':')
        r.sendline('1')
        msg = r.recvline().strip().decode().split(':')[1].strip()
        assert len(msg) == 2920, len(msg)
        texts.append(msg)
    r.close()

out = ''
for i in range(2920):
    ct = [0, 0]
    for text in texts:
        ct[int(text[i])] += 1
    print(ct)
    assert max(ct) * 2 >= min(ct) * 3

    if ct[0] > ct[1]:
        out += '0'
    else:
        out += '1'

print(out)

msg = ''
for i in range(0, len(out), 5):
    for j in range(i, i+5):
        assert out[i] == out[j]
    msg += out[i]

print(int(msg, 2).to_bytes(len(msg) // 8, 'big'))
