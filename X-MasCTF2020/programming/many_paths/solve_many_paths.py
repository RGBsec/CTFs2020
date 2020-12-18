from ast import literal_eval
from pwn import remote
from subprocess import Popen, PIPE

mxn = 0
mxl = 0

def parse_input(s: bytes):
    s = s.decode()
    print(s.strip())
    assert "That is not the correct answer!" not in s and "Bad input, I was expecting an integer. Aborting!" not in s
    N, L = 0, 0
    mat = []
    forbidden = []
    for line in s.split('\n'):
        if line.startswith("N = "):
            N = int(line.split()[-1])
        elif line.startswith("L = "):
            L = int(line.split()[-1])
        elif line.startswith('0,') or line.startswith('1,'):
            mat.append([c for c in line.split(',')])
        elif line.startswith("forbidden nodes: "):
            forbidden = literal_eval(line.split()[-1])
    global mxl, mxn
    mxl = max(mxl, L)
    mxn = max(mxn, N)

    nl = '\n'
    parsed = f"{N} {L} {len(forbidden)}\n{nl.join([' '.join([c for c in row]) for row in mat])}\n{' '.join([str(x) for x in forbidden])}"
    return parsed.encode()


for _ in range(5):
    rem = remote("challs.xmas.htsp.ro", 6053)
    for _ in range(40):
        resp = b''
        while b"L =" not in resp[-10:]:
            cur = rem.recv(timeout=0.25)
            resp += cur

        resp = parse_input(resp)

        print("input done")
        with Popen(["./many_paths.out"], stdin=PIPE, stdout=PIPE) as proc:
            answer = proc.communicate(resp)[0]
            print(">", answer.decode()[:8192])
            rem.send(answer)
        print("answer sent")

    print(rem.recvall(3).decode())

print(mxn, mxl)