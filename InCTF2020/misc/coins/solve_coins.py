from hashlib import sha256
from pwn import remote
from string import ascii_letters, digits

CHARS = ascii_letters + digits
# CHARS += ''.join(list(set([chr(c) for c in range(256)]) - set(CHARS)))
CHARS = CHARS.encode()
print(CHARS)

def solve_pow(ending, target):
    text = bytearray(4) + bytearray(ending)
    for a in CHARS:
        print(a)
        text[0] = a
        for b in CHARS:
            text[1] = b
            for c in CHARS:
                text[2] = c
                for d in CHARS:
                    text[3] = d
                    res = sha256(text).hexdigest()
                    if res == target:
                        return text[:4]
    raise ValueError()

rem = remote("34.74.30.191", 1337)
def query(l, r):
    rem.sendline(f"{l} {r}")
    print(f"{l} {r}")
    resp = rem.recvline().strip().decode()
    print(resp)
    resp = int(resp.split()[11])
    return resp


def check(l, r, ref):
    size = r - l + 1
    result = query(l, r)

    if size % 2 == 0:
        return result != 0
    else:
        return result != ref


def solve(N):
    print(rem.recvline().strip().decode())

    print("N:", N)

    assert N != 2

    if N == 1:
        return 0

    left = query(0, 0)
    right = query(N-1, N-1)
    if left != right:
        other = query(1, 1)
        if left == other:
            return N-1
        else:
            assert right == other
            return 0

    lo = 0
    hi = N-1

    while lo < hi:
        mid = (lo + hi) >> 1
        if check(lo, mid, left):
            hi = mid
        else:
            lo = mid + 1
    return lo


def main():
    challenge = rem.recvline().strip()
    assert rem.recvline().strip() == b"Give me XXXX:"
    
    print(challenge)
    ending = challenge.split(b'+')[1].split(b')')[0]
    target = challenge.split()[2].decode()
    print(ending, target)
    ans = solve_pow(ending, target)

    rem.sendline(ans)
    print(ans)
    
    print(rem.recvline().strip().decode())
    print(rem.recvline().strip().decode())
    while True:
        N = rem.recvline().strip().decode()
        print("n_str:", N)
        if N.startswith("Ahh"):
            break

        N = int(N.split()[8])
        ans = solve(N)
        rem.sendline(f"! {ans}") 
        print(rem.recvline().strip().decode())

    print(rem.recvall(3).strip().decode())

if __name__ == "__main__":
    main()
