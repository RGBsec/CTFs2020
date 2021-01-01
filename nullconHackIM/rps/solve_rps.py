from nullconHackIM2020.rps import *

rbox = [0] * len(sbox)
for i in range(len(sbox)):
    rbox[sbox[i]] = i


def reverse_state(state, c):
    # print("reversing", hex(bytes_to_int(state))[2:], c)
    key = bytearray([0x0F] * 16)
    key[0] = ord(c)

    for _ in range(round):
        temp = bytearray(16)
        for i in range(len(state)):
            temp[i] = state[p[i]]
        state = temp

        for i in range(len(state)):
            state[i] = rbox[state[i]]
        state = repeated_xor(state, key)
    # print("got", hex(bytes_to_int(state))[2:], '\n')
    return state


def unhash(dat):
    states = [int_to_bytes(int(data, 16)) for data in dat]

    chars = ['r', 'p', 's']
    rev_states = [[hex(bytes_to_int(reverse_state(state, chars[i])))[2:] for i in range(3)] for state in states]
    end = False
    idxs = []
    # for rs in rev_states:
    #     #     print(rs)
    for rs in rev_states:
        if end:
            break
        for n in rs:
            if end:
                break
            idxs.clear()
            for st in rev_states:
                if n in st:
                    idxs.append(st.index(n))
            if len(idxs) == 3:
                print("They played:", chars[idxs[0]])
                print("Play:", chars[(idxs[0] + 1) % 3])
                end = True
                break
    print()


if __name__ == '__main__':
    inp = input('>')
    while inp != 'q':
        unhash(inp.split())
        inp = input('>')
