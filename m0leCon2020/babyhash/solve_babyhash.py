from binascii import hexlify
# from Crypto.Util.number import bytes_to_long, long_to_bytes
#
# p = 43401284375631863165968499011197727448907264840342630537012422089599453290392542589198227993829403166459913232354777490444915201356560807401141203961578150815557853865678753463969663318864902106651761912058979552119867603661163587639785030788676120329044248495611269533429749805119341551183130515359738240737511058829539566547367223386189286492001611298474857947463007621758421914760578235374029873653721324392107800911728989887542225179963985432894355552676403863014228425990320221892545963512002645771206151750279770286101983884882943294435823971377082846859794746562204984002166172161020302386671098808858635655367
#
# a = bytes_to_long(b'admin')
# b = bytes_to_long(b'password')
# print(a, b)
# a += p - 1
# b += p - 1
#
# a = long_to_bytes(a)
# print(len(hexlify(a)))
# print(long_to_bytes(0))
# print(bytes_to_long(b'\x00\x00\x00a'))
print(hexlify(b"\x00admin"))
print(hexlify(b"\x00password"))