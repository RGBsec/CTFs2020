from pwn import remote
from time import sleep

from utils.fibonacci import Fibonacci
from utils.rotate import rotate_by


def solve():
    r = remote("misc.2020.chall.actf.co", 20300)

    fib = Fibonacci(50)

    r.recvuntil('--------------------\n')
    for i in range(50):
        sleep(0.1)
        resp = r.recvline().decode()
        if "Sorry" in resp:
            print(resp)
            return
        ctext = resp.split("Shift")[1].strip().split()[0]
        n = int(resp.split('=')[-1])

        print('-'*50)
        print(f"Received problem #{i+1}")
        print("n:", n)
        print("Text:", ctext)

        fn = fib.get(n)
        ans = rotate_by(ctext, fn, start='A')

        if ctext == "by":  # handle case where they send an empty string
            ans = ''
        print("Fib n:", fn)
        print("Sending:", ans)
        r.sendline(ans)

    flag = r.recvall(10).decode().strip().strip(':').strip()
    r.close()
    return flag


if __name__ == "__main__":
    print(solve())