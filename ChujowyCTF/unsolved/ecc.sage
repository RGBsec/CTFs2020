from operator import xor
from public import p, g
from secret import flag, a_s, b_s


def add(F, p1, p2):
    try:
        return {p1: p2, p2: p1}[-1]
    except:
        pass
    x1, y1 = p1
    x2, y2 = p2
    x3 = FF(x1*x2 - x1*y2 - x2*y1 + 2*y1*y2) / FF(x1 + x2 - y1 - y2 - 1)
    y3 = FF(y1*y2) / FF(x1 + x2 - y1 - y2 - 1)
    return (x3, y3)

def mul(F, x, k):
    acc = -1
    while k:
        if k & 1:
            acc = add(F, x, acc)
        acc = add(F, acc, acc)
        k //= 2
    return acc

def pad(data, length):
    # Assume input is less than 256 bytes.
    return data + bytes([length - len(data)] * (length - len(data))) 

def encrypt(data, stream):
    return xor(int(data), int(stream))

def encrypt_bytes(data, key):
    data = pad(data, int(key).bit_length() // 8)
    return encrypt(int.from_bytes(data, 'big'), key)

FF = Zmod(p)
A = mul(FF, g, a_s)
B = mul(FF, g, b_s)
print(f'g = {g}', f'p = {p}', f'A = {A}', f'b = {B}', sep='\n')
a_ms = mul(FF, B, a_s)
b_ms = mul(FF, A, b_s)
assert a_ms == b_ms
shared = a_ms[0] * a_ms[1]


print(f'len = {len(flag)}, enc = {encrypt_bytes(flag, shared)}')

# g = (375383228397780342292610905741415543021123193893202993933376546008355999579881, 125127742799260114097536968580471847673707731297734331311125515336118666526627)
# p = 1017349223066738178194531452435878724694134639196427641168991759143390320356263
# A = (603956890649406768784284509883012839855804103607835093214222589654065615494206, 749634286053611578152285189158606552324508418540678613236591040516722145253708)
# b = (890062254689797703350145707732638943570461065304155615771307683230377614308406, 467371775612631851798003093722695784734930391102311439111204608050476921601852)
# len = 42, enc = 54357159864722158692491564537102129439237984275607683326888133775459718903987000238912076679209103764

