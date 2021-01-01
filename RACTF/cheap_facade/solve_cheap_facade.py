from binascii import crc32

MAX_SIZE = 3000
TARGET = 0x52392a6

with open("cheap_facade.png", 'rb') as img:
    img_bytes = bytearray(img.read())

found = []
for w in range(MAX_SIZE):
    if w % 100 == 0:
        print(w)
    for h in range(MAX_SIZE):
        w_bytes = w.to_bytes(4, 'big')
        h_bytes = h.to_bytes(4, 'big')

        for i in range(4):
            img_bytes[16 + i] = w_bytes[i]
            img_bytes[20 + i] = h_bytes[i]

        if crc32(img_bytes[0xc:0x1d]) == TARGET:
            print("FOUND:", w, h)
            found.append((w, h))

for dims in found:
    print(dims)
    w_bytes = dims[0].to_bytes(4, 'big')
    h_bytes = dims[1].to_bytes(4, 'big')
    for i in range(4):
        img_bytes[16 + i] = w_bytes[i]
        img_bytes[20 + i] = h_bytes[i]

    with open(f"found({dims[0]}x{dims[1]}).png", 'wb+') as f:
        f.write(img_bytes)