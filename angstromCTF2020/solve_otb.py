from pwn import remote
import base64, random, string, time


def otp(a, b):
    r = ""
    for i, j in zip(a, b):
        r += chr(ord(i) ^ ord(j))
    return r


def genSample():
    p = ''.join([string.ascii_letters[random.randint(0, len(string.ascii_letters) - 1)] for _ in range(random.randint(1, 30))])
    k = ''.join([string.ascii_letters[random.randint(0, len(string.ascii_letters) - 1)] for _ in range(len(p))])

    x = otp(p, k)

    return x, p, k


def sample_str():
    x, p, k = genSample()
    return f'{base64.b64encode(x.encode()).decode()} with key {base64.b64encode(k.encode()).decode()}'


if __name__ == "__main__":
    while time.time() - int(time.time()) > 0.0001:
        time.sleep(0.00001)

    r = remote("misc.2020.chall.actf.co", 20301)
    random.seed(int(time.time()))

    time.sleep(1)
    print(r.recvline())
    r.recvuntil(b'>')
    r.sendline('2')
    resp = r.recvline().decode().strip()

    x, p, k = genSample()
    r.sendline(p)
    print(r.recvall())
