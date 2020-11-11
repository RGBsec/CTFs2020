import binascii
from base64 import b64decode

encoded = []
ciphertexts = []
with open("assignment.txt", 'r') as f:
    cur = ""
    for line in f:
        if len(line.strip()) == 0 and cur:
            try:
                if '-----' not in cur and "/tmp/exfil" not in cur:
                    ciphertexts.append(b64decode(cur))
                    encoded.append(cur)
                cur = ""
            except binascii.Error:
                pass
        elif "While digging" not in line and "transmit" not in line and "known" not in line:
            cur += line.strip()

for i in range(9):
    with open(f"{i}.enc", 'wb') as f:
        f.write(b''.join([ct[i*16:(i+1)*16] for ct in ciphertexts]))