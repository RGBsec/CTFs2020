"""
Writeup for Hexion CTF 2020
By Stanley
Challenge: PIL
Category: Reversing
Points: 977 (as of time of writing)
Description:
    Our team detected a suspicious image, and managed to get a code of some sort, and we think they are related.
    Can you investigate this subject and see if you can give us more data?
    Author: Idan
Hint: PIL = PI + IL

A BMP image and C# bytecode file are provided. One of my teammates used a decompiler from JetBrains to recover the original C# program. See here: https://pastebin.com/aHMP04xj
I wrote a python program to emulate what the C# program does, since I don't know C# and didn't want to have to keep checking the docs to understand what was happening.
We have a main and 2 functions. GetNextPiDigit's purpose is obvious, although I originally had some confusion over whether the one-million-digits.txt started with 3.14, 314, or 14.
Hide is where everything happens. Secret is converted into bytes, which are then converted into 8 bits appended into an array. The rest is pretty straighforward, although the (byte) (254U & (uint) bytes[index2]) part confused our team for a little while. It turns out that sets the least significant bit of bytes[index2] to 0.
Then the next line adds a bit from the bitarray to bytes[index2], so what we have here is basically LSB steganography based on digits of pi.

Once that's clear, we can write a program to recover the flag. This is mostly straightforward. The only issue is what the start of the pi digits file is, but you can try 3.14, 314, and 14 and see which one is right.
"""

# my file with one million digits of pi is called pi-million since I think it's more descriptive
file = open("pi-million.txt", 'r')
# the million pi digits start with 14159, not 3


# taken from the source and converted into python
def get_next_pi_digit() -> int:
    num = ord(file.read(1))
    if num == 10:
        num = ord(file.read(1))
    return num - 48


# taken from the source and converted into python
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


# python version of Convert.ToByte
def bits_to_int(bits: list) -> int:
    ret = 0
    for bit in reversed(bits):
        ret *= 2
        ret += bit
    return ret


# reversing Hide
def recover(out_path):
    # read bytes from result image
    with open(out_path, 'rb') as f:
        out_bytes = f.read()
    out_bytes = bytearray(out_bytes)
    # print(out_bytes)

    res_bits = []  # bits that will hold our flag
    num1 = int(out_bytes[14]) + 14

    # copy the loop from hide, but read the lsb from out_bytes[idx2] instead
    for idx1 in range(int(1e3)):  # 1e3 was a rather arbitrary number - I started with 1e4 but it took too long so here we are
        idx2 = num1 + get_next_pi_digit()
        # print(idx1, idx2)
        res_bits.append(out_bytes[idx2] % 2)
        num1 += 10

    # print(res_bits)
    # just to be safe, in case some other bits came in at the start, shift the bits so each combination will be printed
    for sh in range(8):
        nums = [bits_to_int(res_bits[sh+i:sh+i+8]) for i in range(0, len(res_bits), 8)]
        secret = ''.join([chr(num) for num in nums])
        # check if the flag is in the recovered secret
        if "hex" in secret.lower() or b"hex" in secret.encode("UTF-8").lower():
            print(secret.encode("UTF-8"))  # make sure to encode in UTF-8, since that's how the bitArray was created


def main():
    # hide("original.bmp", "result.bmp", "<CENSORED>")
    recover("result.bmp")


if __name__ == "__main__":
    main()

# hexCTF{l00k_wh0_l3arned_t0_sp34k_byt3c0de}
