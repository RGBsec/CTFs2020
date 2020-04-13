file = open("pi-million.txt", 'r')
# the million pi digits start with 14159, not 3


def get_next_pi_digit() -> int:
    num = ord(file.read(1))
    if num == 10 or num == ord('\n') or num == ord('.'):
        num = ord(file.read(1))
    return num - 48


def hide(src_path: str, dst_path: str, secret: str):
    bit_array = []
    for b in secret.encode():
        bit_array.extend([(b >> i) % 2 for i in range(8)])

    with open(src_path, 'rb') as f:
        src_bytes = f.read()

    src_bytes = bytearray(src_bytes)
    num1 = int(src_bytes[14]) + 14
    for idx1 in range(len(bit_array)):
        idx2 = num1 + get_next_pi_digit()
        num2 = int(254 & int(src_bytes[idx2]))
        src_bytes[idx2] = num2 + bit_array[idx1]
        num1 += 10

    with open(dst_path, 'wb') as outfile:
        outfile.write(src_bytes)


def bits_to_int(bits: list) -> int:
    ret = 0
    for bit in reversed(bits):
        ret *= 2
        ret += bit
    return ret


def recover(out_path):
    with open(out_path, 'rb') as f:
        out_bytes = f.read()
    out_bytes = bytearray(out_bytes)
    # print(out_bytes)

    res_bits = []
    num1 = int(out_bytes[14]) + 14
    for idx1 in range(int(1e3)):
        idx2 = num1 + get_next_pi_digit()
        # print(idx1, idx2)
        res_bits.append(out_bytes[idx2] % 2)
        num1 += 10

    # print(res_bits)
    for sh in range(8):
        nums = [bits_to_int(res_bits[sh+i:sh+i+8]) for i in range(0, len(res_bits), 8)]
        secret = ''.join([chr(num) for num in nums])
        if "hex" in secret.lower() or b"hex" in secret.encode("UTF-8").lower():
            print(secret)
            print(secret.encode("UTF-8"))


def main():
    # hide("original.bmp", "result.bmp", "<CENSORED>")
    recover("result.bmp")


if __name__ == "__main__":
    main()