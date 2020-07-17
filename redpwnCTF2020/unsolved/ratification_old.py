#!/usr/bin/env python3
import numpy as np
from Crypto.Util.number import *
from random import randint

# flag = open('flag.txt','rb').read()
flag = ''

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 65537

message = bytes_to_long(b'redpwnCTF is a cybersecurity competition hosted by the redpwn CTF team.')


def menu():
    print()
    print('[1] Sign')
    print('[2] Verify')
    print('[3] Exit')
    return input()


print("p:", p)
print("q:", q)
print("n:", n)

while True:
    choice = menu()

    if choice == '1':
        # msg = bytes_to_long(input('Message: ').encode())
        msg = int(input("Number: "))
        if msg == message:
            print('Invalid message!')
            continue

        n1 = [randint(0, 11) for _ in range(29)]
        n2 = [randint(0, 2 ** (max(p.bit_length(), q.bit_length()) - 11) - 1) for _ in range(29)]
        a = sum(n1[i] * n2[i] for i in range(29))

        enc = [pow(msg, i, n) for i in n2]
        P = np.prod(list(map(lambda x, y: pow(x, y, p), enc, n1)))
        Q = np.prod(list(map(lambda x, y: pow(x, y, q), enc, n1)))

        b = inverse(e, (p - 1) * (q - 1)) - a
        sig1 = b % (p - 1) + randint(0, q - 2) * (p - 1)
        sig2 = b % (q - 1) + randint(0, p - 2) * (q - 1)
        print(sig1, sig2)
        print("n1:", n1)
        print("n2:", n2)
        print("a:", a)
        print("b % (p-1):", sig1 % (p - 1))
        print("P % p:", P % p)
        print("Q % q:", Q % q)
        print("inv(p,q):", inverse(p, q))
        print("p*inv(p,q)%q:", p * inverse(p, q) % q)
        print("p*inv(p,q)%n:", p * inverse(p, q) % n)

        sp = pow(msg, sig1, n) * P % p
        sq = pow(msg, sig2, n) * Q % q
        print("sp:", sp)
        print("sq:", sq)
        print("p*inv(p,q)*sq%n:", p * inverse(p, q) * sq % n)
        print("q*inv(q,p)*sp%n:", q * inverse(q, p) * sp % n)
        s = (q * inverse(q, p) * sp + p * inverse(p, q) * sq) % n

        print(s)
        print(pow(msg, b+a, n))
        print("Signed!")

    elif choice == '2':
        try:
            msg = bytes_to_long(input('Message: ').encode())
            sig = int(input('Signature: '))
            if pow(sig, e, n) == msg:
                print("Verified!")
                if msg == message:
                    print("Here's your flag: {}".format(flag))
            else:
                print("ERROR HAS OCCURRED...")
        except:
            print("Invalid signature!")

    elif choice == '3':
        print("Good bye!")
        break
