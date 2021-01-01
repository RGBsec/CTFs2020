from pwn import remote
from random import randint

rem = remote("chall.csivit.com", 30721)


def query(friend, amount) -> str:
    print(f"1 {friend+1} {amount}")
    rem.sendline(f"1 {friend+1} {amount}")
    resp = rem.recvline().strip().decode()
    assert resp in ['G', 'E', 'L'], resp
    return resp


def main():
    N = 300
    LIMIT = 1000
    MAX_VAL = 1000000
    amounts = [0] * N
    ct = 0
    cur_mx = 1

    while ct < LIMIT:
        print(amounts)
        if min(amounts) > 0:
            break
        while True:
            cur = randint(0, N-1)
            if amounts[cur] == 0:
                break

        ct += 1
        if query(cur, cur_mx) != 'G':
            amounts[cur] = cur_mx
            continue
        if ct == LIMIT:
            break

        lo = cur_mx + 1
        hi = MAX_VAL
        mid = -1
        while lo < hi:
            mid = (lo + hi) // 2
            resp = query(cur, mid)
            ct += 1
            if ct == LIMIT:
                break
            if resp == 'E':
                break
            elif resp == 'L':
                if mid <= cur_mx:
                    break
                hi = mid - 1
            else:
                lo = mid + 1
        amounts[cur] = mid
        cur_mx = max(cur_mx, mid)

    rem.sendline(f"2 {max(amounts)}")

    print(rem.recvall().decode())
    print("Used", ct, "queries")


if __name__ == "__main__":
    main()