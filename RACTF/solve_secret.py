import base64

"""
-*-*-*- BEGIN ARR ESS AYY MSG -*-*-*-
 0000000000000000000000000000000
 0000000000000000000000000000000
 0000000000000000000000000000000
 0000000000000000000000000000000
 0000000000000000000000000000000
 00000s&nYASMBl==Raa6f1mSybO1&`P
 n=MSlA^HVasQovKL?f9nB=?Wjz*-}bj
 4rNeU}9v(Tcn16Ji;Mjv?)4T@pD@76=
 9j%)LevT&=&p%BMcIckO@P450UqkjIR
 6DT^igJmh5<xI<alHa3p;VuZ%5HWp>1
            #T6e(?T*2I
              00962
 jx@>fERjV6gRSH!+pdv<kOoEVD#<P05
 <nAMIT@fYQOcbQ{VfQh+sli_--_zE8)
 G@9Y^2j=XLkGz;kZTPS&eJtOKwM~!V6
 SmtDRCJ%568a_utlnc?ywyQ^??W!-Ro
 `%%d9c?q+nQ*s<4Sn4@*0vXe9sl<*c8
              *WY0^
-*-*-*- END ARR ESS AYY MSG -*-*-*-
"""


def encrypt(message):
    p, q = rsa.prime_pair(bits=1024)
    ct = base64.b85encode(rsa.encrypt(rsa.solve_for(p=p, q=q, e=e), message.encode()))
    ct = b'\n'.join(ct[i:i + 31].center(41) for i in range(0, len(ct), 31))
    p, q = int.to_bytes(p, 128, 'big'), int.to_bytes(q, 128, 'big')
    s, key = 0, bytearray()
    for (i, j) in zip(p, q):
        key.append(i ^ s)
        key.append((j ^ (s := s ^ i), s := s ^ j)[0])
    key = base64.b85encode(key)
    key = b'\n'.join(key[i:i + 31].center(41) for i in range(0, len(key), 31))
    e_str = base64.b85encode(int.to_bytes(e, 4, 'big')).center(41)
    return b'  -*-*-*- BEGIN ARR ESS AYY MSG -*-*-*-\n' + key + b'\n' + e_str + b'\n' + ct + b'\n' + b'   -*-*-*- END ARR ESS AYY MSG -*-*-*-\n'


e = base64.b85decode("00962")
e = int.from_bytes(e, 'big')

key = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000s&nYASMBl==Raa6f1mSybO1&`Pn=MSlA^HVasQovKL?f9nB=?Wjz*-}bj4rNeU}9v(Tcn16Ji;Mjv?)4T@pD@76=9j%)LevT&=&p%BMcIckO@P450UqkjIR6DT^igJmh5<xI<alHa3p;VuZ%5HWp>1#T6e(?T*2I"
key = bytearray(base64.b85decode(key))
print(key)

ct = "jx@>fERjV6gRSH!+pdv<kOoEVD#<P05<nAMIT@fYQOcbQ{VfQh+sli_--_zE8)G@9Y^2j=XLkGz;kZTPS&eJtOKwM~!V6SmtDRCJ%568a_utlnc?ywyQ^??W!-Ro`%%d9c?q+nQ*s<4Sn4@*0vXe9sl<*c8*WY0^"
ct = base64.b85decode(ct)
print(ct)

assert len(key) == 256, len(key)

s = 0
p = bytearray()
q = bytearray()
for i in range(0, len(key), 2):
    pp = key[i] ^ s
    qq = key[i+1] ^ key[i]
    s = s ^ pp ^ qq
    p.append(pp)
    q.append(qq)
p = int.from_bytes(p, 'big')
q = int.from_bytes(q, 'big')


from sympy import isprime
assert isprime(p) and isprime(q)

from utils.basics import hex_to_ascii
from utils.rsa.rsa_util import plaintext_pq

print(hex_to_ascii(plaintext_pq(int.from_bytes(ct, 'big'), e, p, q)))