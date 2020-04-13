from utils.rsa.rsa_util import to_ascii
from utils.rsa.rsa_lsb_oracle import lsboracle
from pwn import remote


r = remote("challenges1.hexionteam.com", 5000)


def comm(msg: int) -> int:
    r.sendline(str(msg))
    return int(r.recvline().decode().strip().strip('>').strip())


def main():
    flag = int(r.recvline().decode().split(": ")[1].strip())

    assert r.recvline() == b'One encrypt:\n'

    r.recvuntil("m => ")
    r.sendline("-1")
    N = int(r.recvline()) + 1
    print("N:", N)
    assert r.recvline() == b'Alot of unhelpful decrypts:\n'

    dec = lsboracle(flag, comm, 65537, N)
    print(dec)
    print(to_ascii(dec))


if __name__ == "__main__":
    main()
