import os
import socket
from Crypto.Cipher import AES

HOST = ''
PORT = 50007
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

n = 128
m = 2**n

x = [int.from_bytes(os.urandom(n//8),'big') for _ in range(4)] #private key
e1 = (x[0] * x[1]) % m
e2 = (x[2]**2 + 3 * x[3]) % m
p1 = (e1**2 - 2 * e1 * e2 + 2 * e2**2) % m
p2 = (e1 * e2) % m
s.sendall(str(p1).encode()+b'\n')
s.sendall(str(p2).encode())
r = ''
while True:
	c = s.recv(1).decode()
	if c != '\n':
		r += c
	else:
		break
p3 = int(r)
p4 = int(s.recv(1024).decode())
e3 = (p3 + 4 * p4) % m
e4 = pow(3, p3 * e3, m)
e5 = pow(e1, 4, m)
e6 = pow(e2, 4, m)
e7 = (e5 + 4 * e6) % m
k = pow(e4, e7, m)
key = int.to_bytes(k, 16, 'big')

cipher = AES.new(key, AES.MODE_ECB)
flag = s.recv(1000000)
print(cipher.decrypt(flag))
s.close()
