from collections import deque
from math import gcd
from time import sleep

from pwn import remote

r = remote("challenges.ctfd.io", 30267)


def lines(n, print_lines=True):
    try:
        for _ in range(n):
            ln = r.recvline().decode()
            if print_lines:
                print(ln.strip())
    except EOFError:
        return False
    return True


def solve(number):
    r.sendline(str(number))
    r.recvuntil("Dr. J needs help sorting the following veggies into alphabetical order:\n")
    lines(1)

    for i in range(3):
        seq = r.recvline().decode().split(',')
        seq = [x.strip() for x in seq]
        if i == 0 and number != 4:
            lines(2)
        print("seq:", seq)
        if number == 3:
            ans = solve3(seq)
        elif number == 4:
            lines(1)
            line = r.recvline().decode().split()
            x, y = int(line[-7]), int(line[-1])
            ans = solve4(seq, x, y)
        else:
            ans = []
            ok = False
            while not ok:
                ok = True
                for i in range(len(seq) - 1):
                    if seq[i] > seq[i + 1]:
                        seq[i], seq[i + 1] = seq[i + 1], seq[i]
                        ans.append(i)
                        ok = False
        # print("ans:", ans)
        r.sendline(' '.join([str(idx) for idx in ans]))
        lines(3)
        assert b"That's correct!!" in r.recvline()
        if not lines(2):
            break


def solve3(seq):
    seq = deque(seq)
    anchor = min(seq)
    print("anchor:", anchor)

    ans = []
    ct = 0
    while ct <= len(seq):
        if seq[0] > seq[1] and seq[1] != anchor:
            ct = 0
            seq[0], seq[1] = seq[1], seq[0]
            ans.append('s')
        else:
            ct += 1
        ans.append('c')
        seq.append(seq.popleft())
    while seq[0] != anchor:
        ans.append('c')
        seq.append(seq.popleft())

    return ans


def is_sorted(d):
    for i in range(1, len(d)):
        if d[i - 1] > d[i]:
            return False
    return True


def normalize(d):
    seq = d.copy()
    while min(seq) != seq[0]:
        seq.append(seq.popleft())
    return seq


def solve4(seq, x, y):
    def swap(a, b):
        if a == b:
            return []
        if a > b:
            a, b = b, a
        print(a, b)

        i, j = a, b
        ret = []
        while i != x:
            i = (i - 1) % N
            j = (j - 1) % N
            seq.append(seq.popleft())
            ret.append('c')

        ret.append('s')
        seq[x], seq[y] = seq[y], seq[x]

        while min(seq) != seq[0]:
            seq.append(seq.popleft())
            ret.append('c')

        if y == j:
            return ret
        ret.extend(swap(y, j))

        while i != x:
            i = (i - 1) % N
            j = (j - 1) % N
            seq.append(seq.popleft())
            ret.append('c')
        ret.append('s')
        seq[x], seq[y] = seq[y], seq[x]

        while min(seq) != seq[0]:
            seq.append(seq.popleft())
            ret.append('c')
        return ret

    N = len(seq)
    seq = deque(seq)
    ans = []
    if x > y:
        x, y = y, x

    print("N:", N)

    diff = y - x
    assert gcd(diff, N) == 1, gcd(diff, N)

    print(seq)
    print(swap(0, 4))


def exploring():
    def hash_deque(d):
        return '$'.join([str(x) for x in d])

    seq = deque([3, 9, 4, 1, 5, 8, 10, 7, 2, 6])
    # print(solve4(seq, 2, 4))
    x, y = 1, 4
    assert gcd(y - x, len(seq)) == 1, gcd(y - x, len(seq))
    seen = set()
    moves = ''
    q = deque([(seq.copy(), '')])
    while q:
        cur, moves = q.popleft()
        # print(cur)
        if is_sorted(cur):
            print(moves)
            break

        cur.append(cur.popleft())
        hashed = hash_deque(cur)
        if hashed not in seen:
            seen.add(hashed)
            q.append((cur.copy(), moves + 'c'))

        min_idx = cur.index(min(cur))
        if min_idx in (x, y):
            continue
        cur[x], cur[y] = cur[y], cur[x]
        hashed = hash_deque(cur)
        if hashed not in seen:
            seen.add(hashed)
            q.append((cur.copy(), moves + 'cs'))

    print(seq)
    for move in moves:
        if move == 'c':
            seq.append(seq.popleft())
        else:
            seq[x], seq[y], = seq[y], seq[x]
        print(move, seq)


def test():
    from random import shuffle, randint, seed
    seed(0)
    for L in range(7, 100):
        for i in range(1000):
            perm = list(range(L))
            shuffle(perm)

            x, y = randint(0, L - 1), randint(0, L - 1)
            if x > y:
                x, y = y, x
            while gcd(y - x, L) != 1 or x + 1 >= y or (x == 0 and y + 1 == L):
                x, y = randint(0, L - 1), randint(0, L - 1)
                if x > y:
                    x, y = y, x
            print(perm, x, y)
            print(solve4(perm, x, y))


if __name__ == "__main__":
    # solve(4)
    # solve4([0, 4, 2, 5, 1, 3], 1, 2)
    test()

# [5, 1, 0, 2, 3, 4] 0 5
# [6, 0, 4, 2, 1, 3, 5] 0 6
# [0, 4, 2, 5, 1, 3] 1 2
