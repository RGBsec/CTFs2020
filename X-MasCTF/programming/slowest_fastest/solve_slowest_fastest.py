from pwn import remote
from subprocess import Popen, PIPE
from time import time


def parse_line(line):
    return [int(x.split(' = ')[1]) for x in line.split(', ')]


def parse_input(s: bytes):
    s = s.decode()

    for line in s.split('\n'):
        if len(line) == 0:
            continue
        elif line[0] == 'N':
            N, K = parse_line(line)
        elif line[0] == 'P':
            P, Q = parse_line(line)
        elif line[0] == 'v':
            v0, A, C, MOD = parse_line(line)

    parsed = f"{N} {K}\n{P} {Q}\n{v0} {A} {C} {MOD}"
    return parsed.encode()


rem = remote("challs.xmas.htsp.ro", 6055)
rem.recvuntil("2, n\n\n")
start = time()
for i in range(100):
    resp = rem.recvuntil(b"\n\n")
    print(time() - start)
    resp = parse_input(resp)

    with Popen(["./slowest_fastest.out"], stdin=PIPE, stdout=PIPE) as proc:
        answer = proc.communicate(resp)[0]
        # print(">", answer.decode())
        rem.send(answer)
    print(f"Finished test #{i+1} at {time() - start}")

print(rem.recvall(3).decode())

