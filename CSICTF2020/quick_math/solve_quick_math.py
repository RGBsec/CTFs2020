"""Ben has encrypted a message with the same value of 'e' for 3 public moduli - n1 = 86812553978993 n2 = 81744303091421 n3 = 83695120256591 and got the cipher texts - c1 = 8875674977048 c2 = 70744354709710 c3 = 29146719498409. Find the original message. (Wrap it with csictf{})"""
from math import gcd
from sympy import isprime, mod_inverse

n = [86812553978993, 81744303091421, 83695120256591]
c = [8875674977048, 70744354709710, 29146719498409]

assert all([isprime(nn) for nn in n])

totients = [nn - 1 for nn in n]
for e in range(1, 1 << 16 + 2):
    try:
        msgs = []
        for i in range(3):
            d = mod_inverse(e, totients[i])
            msgs.append(pow(c[i], d, n[i]))

        if msgs[0] == msgs[1] and msgs[1] == msgs[2]:
            msg = msgs[0]
            print(msg)
            msg = int(str(msg), 16)
            print("csictf{" + msg.to_bytes(6, 'big').decode() + "}")
            break
    except ValueError:
        pass
