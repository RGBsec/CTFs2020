frmt = b"unictf{"

init_state = b"\x90\x9c\t\xc5\x9aP`5Ez\xf6\x98\xb7\xe5#\x9fR\x13\x9eJ\xd3\xf6'{\x19f;p\xb0\x85E\xeb\x9e\xbd\xc8\xfai\xf3\x9a@"
crib = [frmt[i] ^ init_state[i] for i in range(len(frmt))]

print(crib)
print(bytes(crib))
print(int.from_bytes(crib + [0], 'little'))