from itertools import combinations
from string import ascii_uppercase, digits


def gromark_encrypt(primer: list, key: str, plaintext: str) -> str:
    ct_alphabet, full_key = alphabet_and_key(primer, key, plaintext)
    encrypted = ''.join([ct_alphabet[(ord(char) - ord('A') + full_key[i]) % len(ct_alphabet)]
                         for i, char in enumerate(plaintext.upper())])
    return encrypted


def gromark_decrypt(primer: list, key: str, ciphertext: str) -> str:
    ct_alphabet, full_key = alphabet_and_key(primer, key, ciphertext)
    decrypted = ''.join([ascii_uppercase[ct_alphabet.index(char) - full_key[i] % 26]
                         for i, char in enumerate(ciphertext.upper())])
    return decrypted


def alphabet_and_key(primer: list, key: str, plaintext: str) -> tuple:
    # assert primer.isdecimal() and len(primer) == 5, primer
    # assert len(key) <= 26 and len(key) == len(set(key)) and key.isalpha(), key
    # assert plaintext.isalpha(), plaintext
    N = len(primer)
    # key = key.upper()
    key_chars = set(key)
    t_rows = (26 + len(key) - 1) // len(key)
    table = ['' for _ in range(t_rows)]
    table[0] = key
    c = 0
    for i in range(1, t_rows):
        col = 0
        while col < len(key):
            if c >= 26:
                break
            if ascii_uppercase[c] not in key_chars:
                table[i] += ascii_uppercase[c]
                col += 1
            c += 1
    order = [sorted(key).index(c) for c in key]
    col_order = [order[n] for n in order]
    ct_alphabet = []
    for col in col_order:
        for row in table:
            if col < len(row):
                ct_alphabet.append(row[col])
    # assert len(ct_alphabet) == 26, ct_alphabet
    # assert ct_alphabet.isupper(), ct_alphabet
    full_key = [int(n) for n in primer]
    for i in range(N, len(plaintext)):
        full_key.append((int(full_key[i - N]) + int(full_key[i - N + 1])) % 10)
    return ct_alphabet, full_key


def main():
    ciphertext = "BFPNUDXTEAIDDTKVDSSYNJCYCHETNSYDWVPZWHBAFCMANCDWOVIZJOBVTNLTNFPKMXIODYUMCJRXDPAZQZFRBUXZLZZTLVDJJVAKEYMRTYTMHWXAMPXTWEKCWNSYHREYBGAZFRQSMJNNXRBJMUVDZICUFJXYIQSHJMXCVABIDYSMQLNOPZGJJFLUCSPPKSAYZMXOQYOSSNJLDCNJAMBLXYNBFLXCUAKOHHCBERIAWXEVXCGLBQONILXWYATYHMHGSOMFLEZMGEFCRQTKWMFVWNGHXZZPXRWYWNNATZTGYAKVBKGLFBYBCZIWOTKBEQJILXONLTCYETBUDGJFBTHTEVKCHXVEDXXPBXENZEYGINKNMKYWXTXNEMOAOCRGXBGXQXYWHQIYXBOBEVDGADNXTDFDYDGCFZNKGHHDWQKXYCFJIIGSDJVFREIWQMNYPMXMKZIZRBOBHDRBEASHYNXZXSGEHPEPMVLKWXEUUKAOMWOWJFDLBKHERLPARJMJU"
    key_order = [0, 3, 2, 4, 1, 5]
    prev = '.'
    for key in combinations(ascii_uppercase, r=6):
        ordered_key = ''.join(key[i] for i in key_order)
        if key[3] != prev:
            print(key)
            prev = key[3]
        for primer in combinations(digits, r=5):
            if primer[0] == '0':
                continue
            dec = gromark_decrypt(primer, ordered_key, ciphertext)


def test():
    plain = 'thereareuptotensubstitutesperletter'.upper()
    enc = gromark_encrypt([2, 3, 4, 5, 2], "ENIGMA", plain)
    dec = gromark_decrypt([2, 3, 4, 5, 2], "ENIGMA", enc)
    print(enc)
    print(dec)
    print(plain == dec)


if __name__ == '__main__':
    main()
