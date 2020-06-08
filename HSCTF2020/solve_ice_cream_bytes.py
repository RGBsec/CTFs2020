def rev_toppings(in_bytes: bytearray) -> bytearray:
    toppings = [4, 61, -8, -7, 58, 55, -8, 49, 20, 65, -7, 54, -8, 66, -9, 69, 20, -9, -12, -4, 20, 5, 62, 3, -13, 66,
                8, 3, 56, 47, -5, 13, 1, -7]

    out_bytes = bytearray()
    for in_byte, topping in zip(in_bytes, toppings):
        out_bytes.append(in_byte - topping)
    return out_bytes


def rev_chocolate(in_bytes: bytearray) -> bytearray:
    evens = [in_bytes[i] for i in range(0, len(in_bytes), 2)]
    odds = [in_bytes[i] for i in range(1, len(in_bytes), 2)]
    evens.append(evens.pop(0))
    odds = [odds[-1]] + odds
    odds.pop()

    out_bytes = bytearray()
    for i in range(len(in_bytes)):
        if i % 2 == 0:
            out_bytes.append(evens.pop(0))
        else:
            out_bytes.append(odds.pop(0))

    return out_bytes


def rev_vanilla(in_bytes: bytearray) -> bytearray:
    out_bytes = in_bytes
    for i in range(len(out_bytes)):
        if i % 2 == 0:
            out_bytes[i] -= 1
        else:
            out_bytes[i] += 1
    return out_bytes


def rev_strawberry(in_bytes: bytearray) -> bytearray:
    out_bytes = in_bytes
    out_bytes.reverse()
    return out_bytes


def main():
    target = bytearray(
        [108, 111, 108, 108, 111, 111, 107, 97, 116, 116, 104, 105, 115, 116, 101, 120, 116, 105, 103, 111, 116, 102,
         114, 111, 109, 116, 104, 101, 109, 97, 110, 117, 97, 108]
    )
    print("flag{" + rev_strawberry(rev_vanilla(rev_chocolate(rev_toppings(target)))).decode() + "}")

    # flag{ig3_cr34m_byt3s_4r3_4m4z1n9_tr34ts} is wrong even though it works
    # flag{ic3_cr34m_byt3s_4r3_4m4z1n9_tr34ts} is correct (notice the "c" in "ic3")


if __name__ == '__main__':
    main()