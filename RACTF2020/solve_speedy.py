from socket import socket, AF_INET, SOCK_STREAM
from gmpy import mpz
from math import gcd
from utils.rsa.rsa_util import ciphertext, plaintext_pq, plaintext_pd, plaintext_pphi, modinv


def parse_line(line: str) -> mpz:
    return mpz(line.split(':')[-1])


def make_line(number: mpz) -> bytes:
    return str(number).encode() + b'\n'


def lcm(a, b):
    return a * b // gcd(a, b)


IP = '95.216.233.106'
PORT = 49870

p, q, n, e, phi, pt, ct, d = -1, -1, -1, -1, -1, -1, -1, -1
buffer = b''

s = socket(AF_INET, SOCK_STREAM)
s.connect((IP, PORT))
s.setblocking(False)

while True:
    # Read until a prompt or line break
    try:
        chunk = s.recv(4096)
        buffer += chunk
        print(chunk.decode(), end='')
    except BlockingIOError:
        pass

    if b'\n' not in buffer and not buffer.endswith(b': '):
        continue

    # Grab the oldest line
    buffer = buffer.split(b'\n', 1)
    if len(buffer) == 1:
        line, buffer = buffer[0], b''
    else:
        line, buffer = buffer
    line = line.decode()

    # Lines start with [<code>]
    if line[:1] != '[':
        continue

    mode = line[1]
    if mode == '*':
        pass
    elif mode == 'c':
        print(line)
    elif mode == ':':
        if 'p:' == line[4:6]:
            p = parse_line(line)
        elif 'q' == line[4]:
            q = parse_line(line)
        elif 'n' == line[4]:
            n = parse_line(line)
        elif 'e' == line[4]:
            e = parse_line(line)
        elif 'd' == line[4]:
            d = parse_line(line)
        elif 'pt' == line[4:6]:
            pt = parse_line(line)
        elif 'ct' == line[4:6]:
            ct = parse_line(line)
        elif 'phi' == line[4:7]:
            phi = parse_line(line)
    elif mode == '!':
        if "Correct answer" != line[4:]:
            print(line)
            break
    elif mode == '?':
        if 'n' == line[4]:
            # assert p != -1 and q != -1
            s.send(make_line(p * q))
        elif 'p:' == line[4:6]:
            # assert q != -1 and n != -1
            s.send(make_line(n // q))
        elif 'q' == line[4]:
            # assert p != -1 and n != -1
            s.send(make_line(n // p))
        elif 'd' == line[4]:
            # assert e != -1
            if p != -1 and q != -1:
                # assert phi == -1 or phi == (p-1)*(q-1)
                phi = (p - 1) * (q - 1)
            s.send(make_line(modinv(e, phi)))
        elif 'ct' == line[4:6]:
            # assert pt != -1 and e != -1, pt
            if n == -1:
                # assert p != -1 and q != -1
                n = p * q
            s.send(make_line(ciphertext(pt, e, n)))
        elif 'pt' == line[4:6]:
            # assert ct != -1 and e != -1
            if p != -1 and q != -1:
                s.send(make_line(plaintext_pq(ct, e, p, q)))
            # elif p != -1 and n != -1:
            #     s.send(make_line(plaintext_pn(ct, e, p, n)))
            # elif q != -1 and n != -1:
            #     s.send(make_line(plaintext_pn(ct, e, q, n)))
            elif p != -1 and d != -1:
                s.send(make_line(plaintext_pd(ct, p, d)))
            # elif q != -1 and d != -1:
            #     s.send(make_line(plaintext_pd(ct, q, d)))
            # elif n != -1 and d != -1:
            #     s.send(make_line(plaintext_nd(ct, n, d)))
            elif p != -1 and phi != -1:
                s.send(make_line(plaintext_pphi(ct, e, p, phi)))
            # elif q != -1 and phi != -1:
            #     s.send(make_line(plaintext_pphi(ct, e, q, phi)))
            else:
                raise Exception
        elif 'phi' == line[4:7]:
            # assert p != -1 and q != -1
            s.send(make_line((p - 1) * (q - 1)))
        else:
            raise Exception
        p, q, n, e, phi, pt, ct, d = -1, -1, -1, -1, -1, -1, -1, -1
    elif mode == 'F':
        break
    else:
        raise Exception

s.close()
