import socket
import hashlib
import math
import binascii

def apply_secret(c, rev):
    r = bin(c)[2:].rjust(128, '0')
    return int(''.join([str(r[i]) for i in rev]), 2)


def decrypt(n: int, secret: list):
    to_decrypt = n
    for _ in range(9):
        block1 = to_decrypt >> 640
        block2 = (to_decrypt >> 512) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        to_decrypt = (to_decrypt << 128) % (1 << 768)
        x = apply_secret(block2, secret)
        to_decrypt |= x ^ block1

    dec = hex(to_decrypt)
    print(dec)
    dec = dec[2:]
    if len(dec) & 1:
        dec = '0' + dec

    return binascii.unhexlify(dec)

def encrypt(query, s):
    s.send("1\n".encode())
    s.recv(4096)
    s.send((query + "\n").encode())
    return s.recv(4096).decode().split("\n")[0]
def solve_pow(poww, s):
    current = 1
    while True:
        if hashlib.sha256(str(current).encode()).hexdigest().endswith(poww):
            break
        current += 1
    print("[?] Pow Challenge Solution: ", current)
    print("[?] Hash: ", hashlib.sha256(str(current).encode()).hexdigest())
    s.send((str(current) + "\n").encode())

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        secret = [[] for _ in range(128)] 
        s.connect(("challs.m0lecon.it", 11000))
        powchal = s.recv(1024).decode()[49:-2]
        print("[?] Challenge:", powchal)
        solve_pow(powchal, s)
        welcome = s.recv(4096).decode()
        enc_chall = welcome.split("\n")[1]
        print(enc_chall)
        visited = [False for _ in range(128)] 
        for i in range(127):
            if (visited[i]):
                continue
            query = str(hex(1 << i))[2:].rjust(32 * 6, "0")
            result = encrypt(query, s).strip().rjust(32 * 6, "0")
            print(result)
            parts1 = [127 - round(math.log2(int("0x" + result[-32:], 16))), 127 - round(math.log2(int("0x" + result[-64:-32], 16))),
                     127 - round(math.log2(int("0x" + result[-96:-64], 16)))]
            secret[parts1[1]] = parts1[0]
            secret[parts1[1]] = parts1[2]
            visited[parts1[0]] = True
            visited[parts1[1]] = True
            query = str(hex(1 << parts1[0]))[2:].rjust(32 * 6, "0")
            result = encrypt(query, s).strip().rjust(32 * 6, "0")
            print(result)
            parts2 = [127 - round(math.log2(int("0x" + result[-32:], 16))), 127 - round(math.log2(int("0x" + result[-64:-32], 16))),
                     127 - round(math.log2(int("0x" + result[-96:-64], 16))), int("0x" + result[-128:-96], 16),
                     int("0x" + result[-160:-128], 16)]
            secret[parts2[1]] = parts2[0]
            secret[parts2[2]] = parts2[1]
            secret[127 - round(math.log2(parts2[3] ^ (1 << (127 - parts1[1]))))] = parts2[1]
            secret[127 - round(math.log2(parts2[4] ^ (1 << (127 - parts1[2]))))] = parts2[2]
            """visited[parts2[1]] = True
            visited[parts2[2]] = True
            visited[127 - round(math.log2(parts2[3] ^ (1 << (127 - parts1[1]))))]= True
            visited[127 - round(math.log2(parts2[4] ^ (1 << (127 - parts1[2]))))] = True"""





        print(secret)
        missing = 0
        for i in range(128):
            if i not in secret:
                missing = i
                break
        for i in range(128):
            if secret[i] == []:
                secret[i] = missing
                break
        chall = decrypt(int(enc_chall, 16), secret)
        print(chall)
        s.send("2\n".encode())
        s.recv(1024)
        s.send((chall + b"\n"))
        print(s.recv(4096).decode())


if __name__ == "__main__":
    main()