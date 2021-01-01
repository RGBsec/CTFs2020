from hashlib import sha256

with open("original.sav", "rb") as f:
    file = f.read()

print(file)
content = file[:-32]
file_hash = file[-32:]
print(sha256(content).digest())
print(file_hash)