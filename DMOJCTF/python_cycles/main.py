b1 = b'P\x1e\x05\xa3lQ)\x16B\x84\xe2\xc5\x13\xfbH\x9d\xd43(^\xed\x83\xff\x15\xc6\xbb\x06-k4UJ\xa8t\xb7\xa6\xb570%\x03\xe72\xe0\xe8\xef\xb3M@\xdc\x1fT=h$\x93K\x0e\x86\xa9\\\xb8\xe3\x89\x8f\xf4\xa5+\xf7\xcd\x9aC8Iqf\xfdED#\x0bj\x17\xe1z|:\x80S\xfe\xa1\xd8&\xf3\xd6\xec\xb2\xd3w\x04\xee\xa2\x9f,\x85\x02m\xba\x0c\x1a{9\xdd\xcen\xf8\xb1\x92\x8a\xcb\x8c\x12c\xda\xc7oAg\xd1\xe4\rL\x99\xf1\xfa<\xb6\xca\xcc\xde\xd5 \xa0\xae\x82\xa7\xf5\x9b?\xac\xc3\xbc\xc2\xeb\xf6>\xd0!\x1cb;]\xc0\xb4\x10d\x1daxr\x87\x8e\xeae\xab\x18\xe6O\xbdu\n6\t\x88~\x96\xb0\x07\x00\xd91"\x98\xe5\x94\xfcWy\'\xe9\x19\xaf\xc8\x8d/\xbev\xd7\xcf\x95iX[\x97\x7fZ_\xdf\xc9`\xf9\xadY\xf2VF\xa4\xaa\x81\xc4\x90p\x14*s\x08\x8bN\xbf\x9e\x91}\x11G\xdb.\x9c\xc1\x0f\x01\xb9\x1b\xf0\xd25R'
b2 = b'\x1e\x13\x04\x03\x14)\t\x17\x12\x07\x0f\x08\x1a"-\x1d\'\x06\x01\r\x16\x10\x02*(\x00!\x11 .\x1b\x05\x18$/\x0b\x19\x1f\x1c+\x0c&#,\x15%\x0e\n'


def flip_endian(b):
    return int.to_bytes(int.from_bytes(b, 'little'), len(b), 'big')


def sub(arg):
    return bytes((b1[idx] for idx in arg))


def dunno(arg):
    s = arg
    arg = flip_endian(arg)
    arg = flip_endian(arg)
    assert s == arg
    return bytes((arg[idx] for idx in b2))


def pad(s):
    return s + bytes([16 - len(s) % 16] * (16 - len(s) % 16))


def count(cur):
    cur = pad(cur)
    start = cur
    ct = 0
    while True:
        enc = b''
        for i in range(0, len(cur), 16):
            block = cur[i:i + 16]
            block = sub(block)
            enc += block

        cur = dunno(enc)
        ct += 1
        if cur == start:
            break

    return ct


b3 = b'\xa0},\x0c@\x0fn5\xfd\xe4\x9a\xc5X\xb9s|\x14E\xe2Z\x92\x9a\x89>\x9e\xaa\xf1\xad\x7f2_|\x97\xaf\xd2p\x99'
b4 = b'\xbe\xf5@\xddk"\x80cTH\x87iT\x0b\xa4\x15\x8fp\x8f\x14\x9b\xd1$d\x98\xac\x92\'\x13\x80\xdf[}SH\x9f\xac'
res = int.to_bytes(
    pow(count(b3), 65537, 127314748520905380391777855525586135065716774604121015664758778084648831235208544136462397),
    len(b4), 'big')
print(''.join((chr(x ^ y) for x, y in zip(b4, res))))

"""
oOo00oOOooooO0ooOoO00Oo00oOOOooo = int
O0oO0oOooo0Oo0oO0ooOoooOoO0O0OoO = bytes
ooO0oOOOo0Oo0O0o00oo00o0Oo0o00Oo = len
O0OO0O0o00oo0o00O00o0OooOOoO0ooo = range
oOO00O0OO0oO0OOOo00000000O0o0ooo = pow
oOOOO000OOo0OoO00O0oo0ooOOO0o0o0 = zip
OoOoooOoO0O0oOoo0OOo0OoOoOo0OOO0 = chr
Oo0ooOooOo0OO0O0oO00oooO0oOo00O0 = 0
o0oo0ooO00OOo0oO0oOO0o00OO0OooO0 = 1
OoooOooo0ooOoOOo0o0o00O0o0OO0o0o = 16
o0O0OOOooOO00OOOoOoo0oo0o0O00O00 = 'little'
O00oOOo00OOoO00OoO0OoO0000O000O0 = 'big'
OoOOoOoO00oO0O0o0oo0OooOoOoOoO0O = b'P\x1e\x05\xa3lQ)\x16B\x84\xe2\xc5\x13\xfbH\x9d\xd43(^\xed\x83\xff\x15\xc6\xbb\x06-k4UJ\xa8t\xb7\xa6\xb570%\x03\xe72\xe0\xe8\xef\xb3M@\xdc\x1fT=h$\x93K\x0e\x86\xa9\\\xb8\xe3\x89\x8f\xf4\xa5+\xf7\xcd\x9aC8Iqf\xfdED#\x0bj\x17\xe1z|:\x80S\xfe\xa1\xd8&\xf3\xd6\xec\xb2\xd3w\x04\xee\xa2\x9f,\x85\x02m\xba\x0c\x1a{9\xdd\xcen\xf8\xb1\x92\x8a\xcb\x8c\x12c\xda\xc7oAg\xd1\xe4\rL\x99\xf1\xfa<\xb6\xca\xcc\xde\xd5 \xa0\xae\x82\xa7\xf5\x9b?\xac\xc3\xbc\xc2\xeb\xf6>\xd0!\x1cb;]\xc0\xb4\x10d\x1daxr\x87\x8e\xeae\xab\x18\xe6O\xbdu\n6\t\x88~\x96\xb0\x07\x00\xd91"\x98\xe5\x94\xfcWy\'\xe9\x19\xaf\xc8\x8d/\xbev\xd7\xcf\x95iX[\x97\x7fZ_\xdf\xc9`\xf9\xadY\xf2VF\xa4\xaa\x81\xc4\x90p\x14*s\x08\x8bN\xbf\x9e\x91}\x11G\xdb.\x9c\xc1\x0f\x01\xb9\x1b\xf0\xd25R'
o00OO0OOOOo0o0ooooOo0o0000o0OO0o = b'\x1e\x13\x04\x03\x14)\t\x17\x12\x07\x0f\x08\x1a"-\x1d\'\x06\x01\r\x16\x10\x02*(\x00!\x11 .\x1b\x05\x18$/\x0b\x19\x1f\x1c+\x0c&#,\x15%\x0e\n'

def fft(OOooOO0Oo0O0OOO0O0oOOOo0oOO0oOoO):
    return oOo00oOOooooO0ooOoO00Oo00oOOOooo.to_bytes(oOo00oOOooooO0ooOoO00Oo00oOOOooo.from_bytes(OOooOO0Oo0O0OOO0O0oOOOo0oOO0oOoO, o0O0OOOooOO00OOOoOoo0oo0o0O00O00), ooO0oOOOo0Oo0O0o00oo00o0Oo0o00Oo(OOooOO0Oo0O0OOO0O0oOOOo0oOO0oOoO), O00oOOo00OOoO00OoO0OoO0000O000O0)


def ooo0O00O0000oOo0oO0O0o00Oo0ooO0o(OOooOO0Oo0O0OOO0O0oOOOo0oOO0oOoO):
    return O0oO0oOooo0Oo0oO0ooOoooOoO0O0OoO((OoOOoOoO00oO0O0o0oo0OooOoOoOoO0O[oo00o0OOOoo0o0O0O000o0oOooOoOO0o] for oo00o0OOOoo0o0O0O000o0oOooOoOO0o in OOooOO0Oo0O0OOO0O0oOOOo0oOO0oOoO))


def oOO0000000O0O0OOoO00OoO0ooOooOoO(OOooOO0Oo0O0OOO0O0oOOOo0oOO0oOoO):
    OOooOO0Oo0O0OOO0O0oOOOo0oOO0oOoO = fft(OOooOO0Oo0O0OOO0O0oOOOo0oOO0oOoO)
    OOooOO0Oo0O0OOO0O0oOOOo0oOO0oOoO = fft(OOooOO0Oo0O0OOO0O0oOOOo0oOO0oOoO)
    return O0oO0oOooo0Oo0oO0ooOoooOoO0O0OoO((OOooOO0Oo0O0OOO0O0oOOOo0oOO0oOoO[oo00o0OOOoo0o0O0O000o0oOooOoOO0o] for oo00o0OOOoo0o0O0O000o0oOooOoOO0o in o00OO0OOOOo0o0ooooOo0o0000o0OO0o))


def OOo0Oo0Oo0o0oo00OOooOOoO0O00o00o(Oo0O0Oo0OOO0OOo0o0Oo00O0o00O0oo0):
    return Oo0O0Oo0OOO0OOo0o0Oo00O0o00O0oo0 + O0oO0oOooo0Oo0oO0ooOoooOoO0O0OoO([OoooOooo0ooOoOOo0o0o00O0o0OO0o0o - ooO0oOOOo0Oo0O0o00oo00o0Oo0o00Oo(Oo0O0Oo0OOO0OOo0o0Oo00O0o00O0oo0) % OoooOooo0ooOoOOo0o0o00O0o0OO0o0o] * (OoooOooo0ooOoOOo0o0o00O0o0OO0o0o - ooO0oOOOo0Oo0O0o00oo00o0Oo0o00Oo(Oo0O0Oo0OOO0OOo0o0Oo00O0o00O0oo0) % OoooOooo0ooOoOOo0o0o00O0o0OO0o0o))


def ooo0O000O0ooo0ooO0oOo0O0ooOo0oOo(Oo0O0Oo0OOO0OOo0o0Oo00O0o00O0oo0):
    Oo0O0Oo0OOO0OOo0o0Oo00O0o00O0oo0 = OOo0Oo0Oo0o0oo00OOooOOoO0O00o00o(Oo0O0Oo0OOO0OOo0o0Oo00O0o00O0oo0)
    o0OooOOo0Oo0ooOoOOOo000O0oOOO000 = Oo0O0Oo0OOO0OOo0o0Oo00O0o00O0oo0
    Ooo000Oooo00OoOO0O00oOo00oOoO00O = Oo0ooOooOo0OO0O0oO00oooO0oOo00O0
    while True:
        o00ooO0oooOO0o0o00oOO0Ooo00O0ooo = b''
        for oOOO00O0o00o0000OOo0ooo000Oo00OO in O0OO0O0o00oo0o00O00o0OooOOoO0ooo(Oo0ooOooOo0OO0O0oO00oooO0oOo00O0, ooO0oOOOo0Oo0O0o00oo00o0Oo0o00Oo(Oo0O0Oo0OOO0OOo0o0Oo00O0o00O0oo0), OoooOooo0ooOoOOo0o0o00O0o0OO0o0o):
            o0O00o0OO0o00oOoO0OoOo00oo0OOoOo = Oo0O0Oo0OOO0OOo0o0Oo00O0o00O0oo0[oOOO00O0o00o0000OOo0ooo000Oo00OO:oOOO00O0o00o0000OOo0ooo000Oo00OO + OoooOooo0ooOoOOo0o0o00O0o0OO0o0o]
            o0O00o0OO0o00oOoO0OoOo00oo0OOoOo = ooo0O00O0000oOo0oO0O0o00Oo0ooO0o(o0O00o0OO0o00oOoO0OoOo00oo0OOoOo)
            o00ooO0oooOO0o0o00oOO0Ooo00O0ooo += o0O00o0OO0o00oOoO0OoOo00oo0OOoOo

        Oo0O0Oo0OOO0OOo0o0Oo00O0o00O0oo0 = oOO0000000O0O0OOoO00OoO0ooOooOoO(o00ooO0oooOO0o0o00oOO0Ooo00O0ooo)
        Ooo000Oooo00OoOO0O00oOo00oOoO00O += o0oo0ooO00OOo0oO0oOO0o00OO0OooO0
        if Oo0O0Oo0OOO0OOo0o0Oo00O0o00O0oo0 == o0OooOOo0Oo0ooOoOOOo000O0oOOO000:
            break

    return Ooo000Oooo00OoOO0O00oOo00oOoO00O


Oo0O0Oo0OOO0OOo0o0Oo00O0o00O0oo0 = b'\xa0},\x0c@\x0fn5\xfd\xe4\x9a\xc5X\xb9s|\x14E\xe2Z\x92\x9a\x89>\x9e\xaa\xf1\xad\x7f2_|\x97\xaf\xd2p\x99'
oooo0oOoO00OoO00OOoOOO0oo0oO0O0o = b'\xbe\xf5@\xddk"\x80cTH\x87iT\x0b\xa4\x15\x8fp\x8f\x14\x9b\xd1$d\x98\xac\x92\'\x13\x80\xdf[}SH\x9f\xac'
O0O00Oo0Ooo0oOO000o0OoOooOO0000O = oOo00oOOooooO0ooOoO00Oo00oOOOooo.to_bytes(oOO00O0OO0oO0OOOo00000000O0o0ooo(ooo0O000O0ooo0ooO0oOo0O0ooOo0oOo(Oo0O0Oo0OOO0OOo0o0Oo00O0o00O0oo0), 65537, 127314748520905380391777855525586135065716774604121015664758778084648831235208544136462397), ooO0oOOOo0Oo0O0o00oo00o0Oo0o00Oo(oooo0oOoO00OoO00OOoOOO0oo0oO0O0o), O00oOOo00OOoO00OoO0OoO0000O000O0)
print(''.join((OoOoooOoO0O0oOoo0OOo0OoOoOo0OOO0(o0O0OO0oOO00oo0o0ooOooO0Ooooo0o0 ^ oOOoooO00oO0Ooooo00OO0Oo00ooOOOO) for o0O0OO0oOO00oo0o0ooOooO0Ooooo0o0, oOOoooO00oO0Ooooo00OO0Oo00ooOOOO in oOOOO000OOo0OoO00O0oo0ooOOO0o0o0(oooo0oOoO00OoO00OOoOOO0oo0oO0O0o, O0O00Oo0Ooo0oOO000o0OoOooOO0000O))))
"""
