from Crypto.Util.number import bytes_to_long, getPrime, long_to_bytes
from random import randint
# from secret import flag

flag = "hexCTF{local fake flag}"

MIN = randint(0x30, 0x40)
P = 2 ** 521 - 1


def eval_at(poly, x, prime):
    """Evaluates polynomial (coefficient tuple) at x"""
    accum = 0
    for coeff in reversed(poly):
        accum *= x
        accum += coeff
        accum %= prime
    return accum


def main():
    poly = [bytes_to_long(flag.encode())]
    print("poly:", poly)
    poly.extend(set([randint(1, P - 1) for i in range(MIN)]))
    print("poly:", poly)
    print("┌───────────────┐")
    print("│ SSS Encryptor │")
    print("└───────────────┘")
    print("Enter text to encrypt, leave empty to quit.")
    while True:
        data = input(">>> ")
        data = "\x01"
        if bytes_to_long(data.encode()) % P == 0:
            break
        print("dat:", bytes_to_long(data.encode()))
        print(eval_at(poly, bytes_to_long(data.encode()), P))


if __name__ == "__main__":
    pass
    print(long_to_bytes(P))
    # main()
