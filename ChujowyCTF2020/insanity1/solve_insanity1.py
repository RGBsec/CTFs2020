from pwn import remote

answers = ['4', '81', '42123']
cur = 0

while True:
    rem = remote("insanity1.chujowyc.tf", 4004)
    assert rem.recvline().strip() == b"Welcome chCTF Sanity Check :D"

    for ans in answers:
        print(rem.recv().decode().strip())
        print(ans)
        rem.sendline(ans)

    print(rem.recv().decode().strip())
    print(cur)
    rem.sendline(str(cur))
    resp = rem.recv().decode().strip()
    if "Bye" in resp:
        cur += 1
    else:
        print(resp)
        answers.append(str(cur))
    print(rem.recvall(5).decode().strip())