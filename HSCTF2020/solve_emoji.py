from random import randint


def emoji_to_python():
    out = ""
    with open("Emojis.txt", 'r') as prog:
        for line in prog:
            line = line.strip()
            if line.startswith('Input') or line.startswith("//"):
                continue

            if line[0] == '😊':
                if '🎤' in line:
                    out += f"{line[1]} = input()\n"
                elif '📢' in line:
                    out += f"print({line[2]})\n"
                else:
                    out += f"{line[1]} = {line[2]}\n"
            elif line[0] == '😇':
                out += f"{line[1]} += {line[2]}\n"
            elif line[0] == '😈':
                out += f"{line[1]} -= {line[2]}\n"
            elif line[0] == '😵':
                out += f"if {line[1]} != {line[2]}:\n\t"
            else:
                assert False, line

    var_as_emoji = "💔💜💕💞💖♈♉♊♋♌♍♎♏♐♑♒♓🕐🕑🕒🕓🕔🕕🕖🕗🕘🕙🕚🕛"
    var_as_chars = "01248ABCDEFGHIJKLMNOPQRSTUVWX"
    assert len(var_as_emoji) == len(var_as_chars)
    map_emoji_to_var = {var_as_emoji[i]: var_as_chars[i] for i in range(len(var_as_emoji))}

    for k, v in map_emoji_to_var.items():
        out = out.replace(k, v)
    return out


def program(ans):
    # dependencies
    # I:
    # K:
    # G: K, I
    # F: G
    # V: M
    # D: V


    # B: D, E, H
    # C: B, F, (H)
    # J: G, K, B

    # L: B, V, (A)
    # A: C, L

    # E: J, L
    # H: L, I

    M = 0
    A, B, C, D, E, F, G, H, I, J, K, L, V = ans
    if B != V:
        L -= A
    if B != F:
        C = H
    B -= E
    J += G
    if E != J:
        M = D
    C -= 8
    D = V
    V = M
    B += H
    B -= D
    A += L
    C += 4
    D += 2
    if D != F:
        pass
        # R = input()
    if E != J:
        E += J
    L += 1
    K -= 8
    H += I
    F -= G
    if K != 4:
        G += I
    I += 8
    A -= C
    E -= L
    C += C
    H -= L
    if K != 0:
        J -= B

    # print(A)
    # print(B)
    # print(C)
    # print(D)
    # print(E)
    # print(F)
    # print(G)
    # print(H)
    # print(I)
    # print(J)
    # print(K)
    # print(L)
    # print(V)

    def dump():
        print(f"Output: [{A}, {B}, {C}, {D}, {E}, {F}, {G}, {H}, {I}, {J}, {K}, {L}, {V}]")

    dump()
    return [A, B, C, D, E, F, G, H, I, J, K, L, V]


target = "xB^r_En}INc4v"


def main():
    tar = [ord(c) for c in target]

    A, B, C, D, E, F, G, H, I, J, K, L, V = [ord(' ') for _ in tar]
    def dump():
        print(f"Answer: [{A}, {B}, {C}, {D}, {E}, {F}, {G}, {H}, {I}, {J}, {K}, {L}, {V}]")

    I = 73 - 8
    K = 99 + 8
    G = 110 - I
    F = 69 + G
    V = ord('p')
    D = V + 6

    # assume B == F
    B = F - 45
    C = ((94 // 2) - 4) + 8
    H = ((94 // 2) - 4) + 8
    J = 78 + 66 - G

    # sys of eq w/ A, L
    L = 120 + (94 // 2)
    A = 69 + (94 // 2)

    E = 95 + 52 - (J + G)
    # H = 125 + 52 - I

    dump()
    program([A, B, C, D, E, F, G, H, I, J, K, L, V])
    x = [A, B, C, D, E, F, G, H, I, J, K, L, V]

    print("target:", tar)
    print(''.join([chr(m) for m in x]))


if __name__ == '__main__':
    # print(emoji_to_python())
    main()