import base64, bz2
from pwn import remote

rem = remote("tasks.aeroctf.com", 40001)
rem.sendline('Y')
txt = rem.recvall()

print(txt)
print(base64.b85encode(bz2.compress(txt)).decode("UTF-8"))