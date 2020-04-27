# Python RSA implementation 10/01/2020
# Key generation
import json
from struct import unpack

def bytes_to_long(s):
    acc = 0
    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = b"\000" * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', s[i:i+4])[0]
    return acc

VERIFICATION_STRING = "VERIFICATION-UpTheCuts-END\n"

print("Loading public key")
with open("public-key.json") as f:
    pubkey = json.load(f)

plaintext_file = input("Input plaintext filename: ")
output_filename = plaintext_file + ".enc"

with open(plaintext_file) as f:
    p = f.read()

p = bytes_to_long((VERIFICATION_STRING + p).encode("utf-8"))

c = (p**pubkey["e"]) % pubkey["n"]
c = hex(c)

with open(output_filename, "w") as f:
    f.write(c)

print("Output written to " + output_filename)
