from math import log2, ceil

abcd = 0x8ba4c4dfce33fd6101cf5c56997531c024a10f1dc323eb7fe3841ac389747fb90e3418f90011ef2610fa3636cd6cf0002d19faa30d39161fbd45cc58abff6a84
bcd = 0xf969375145322aba697ce9b4e00aa88e81ffe5c306b1b98148f33c4581b2ac39bc95f13b27c39f2311a590b7e27cdbdb7599f615acd70c45378e44fb319b8cb6
ac = 0x855249b385f7b1d9923f71feb3bdee1032963ab51aa7b9d89a20c08c381e77890aa8849702d8791f8e636e833928ba6ea44c5f261983b7e29bd82e44b77fe03b
flag_c_rand = 0xf694bc3d12a0673aead8fc4fdf964f5ec0c1d938e722bf333000f300088ead0dec1e7e03720331098068c13a066ca9bca89850a8ee67feb8471af5f47b4c0f13

a = abcd ^ bcd
print(a)
c = a ^ ac
print(c)

ct = flag_c_rand ^ c
ct_bytes = ct.to_bytes(ceil(log2(ct) / 8), 'big')
print(ct_bytes)
for byte in range(256):
    x = bytearray(ct_bytes)
    for i in range(len(x)):
        x[i] ^= byte
    if x.isascii() and x.decode().isprintable():
        print(x.decode())