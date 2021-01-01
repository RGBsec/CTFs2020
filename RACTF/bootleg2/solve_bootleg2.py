from base64 import b64decode
from pwn import remote
from utils.flag_strings import leet_flag_chars

r = remote("95.216.233.106", 10930)


def send(key: bytes, msg: bytes) -> bytes:
    r.recvuntil("with: ")
    r.sendline(key)
    r.sendline(msg)
    ret = b64decode(r.recvline().decode().split('is:')[1].strip())
    print(key, msg, ret)
    return ret


def get_key():
    with open("plaintext.txt", 'rb') as f:
        plain = f.read()
    with open("ciphertext.txt", 'r') as f:
        enc = b64decode(f.read())

    print(plain)
    print(enc)

    cur_key = bytearray()
    for i in range(1, len(plain)):
        print(cur_key)
        for c in leet_flag_chars.encode():
            if enc.startswith(send(cur_key + bytearray([c]), plain[:i])):
                print(c)
                cur_key += bytearray([c])
                break
        if b'{' in cur_key and b'}' in cur_key:
            break

    print(cur_key)
    return cur_key


def brute_password(key: bytes):
    with open("password.txt", 'r') as f:
        target = b64decode(f.read())

    plain = bytearray(b"ractf{")
    for i in range(100):
        print(plain)
        for c in leet_flag_chars.encode():
            if target.startswith(send(key, plain + bytearray([c]))):
                print(c)
                plain += bytearray([c])
                break
        if b'{' in plain and b'}' in plain:
            break
    print(plain)
    return plain


def main():
    key = get_key()
    # key = b"ractf{n0t_th3_fl49_y3t}"
    print(brute_password(key))


if __name__ == '__main__':
    main()
