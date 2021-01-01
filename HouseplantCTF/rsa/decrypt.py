# Python RSA implementation 10/01/2020
# Key generation
import json
from struct import pack

def long_to_bytes(n, blocksize=0):
    s = b""
    n = int(n)
    while n > 0:
        s = pack('>I', n & 0xffffffff) + s
        n = n >> 32
    for i in range(len(s)):
        if s[i] != b"\000"[0]:
            break
    else:
        s = b"\000"
        i = 0
    s = s[i:]
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * b"\000" + s
    return s

VERIFICATION_STRING = "VERIFICATION-UpTheCuts-END\n"

print("Loading private key")
with open("private-key.json") as f:
    privkey = json.load(f)

input_filename = input("Input filename: ")
output_filename = input("Output filename: ")

with open(input_filename) as f:
    c = f.read()

c = int(c, base=16)

#p = (c**privkey["d"]) % privkey["n"]
p = pow(c, privkey["d"], privkey["n"])
p = long_to_bytes(p).decode("utf-8")

if not VERIFICATION_STRING.replace("\n", "") in p.split("\n")[0]:
    print("Verification check unsuccessful")

p = p.replace(VERIFICATION_STRING, "")

with open(output_filename, "w") as f:
    f.write(p)

print("Output written to " + output_filename)
