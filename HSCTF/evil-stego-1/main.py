# Python 3.8.3

from PIL import Image
from struct import pack, unpack
from typing import List, Tuple
import random


class NotEnoughValuesException(Exception):
    pass


def write_bit(pixels, bit: int, location: Tuple[int, int, int]):
    x, y, channel = location
    orig = list(pixels[x, y])
    orig[channel] &= 0b11111110
    orig[channel] |= bit
    pixels[x, y] = tuple(orig)


def write_byte(pixels, byte: int, locations: List[Tuple[int, int, int]]):
    assert 0 <= byte <= 255
    bits = []
    while byte > 0:
        bits.append(byte % 2)
        byte //= 2
    bits += [0] * (8 - len(bits))
    for i, v in enumerate(bits[::-1]):
        write_bit(pixels, v, locations[i])


def encode(image: Image, message: bytes):
    image = image.convert("RGB")
    pixels = image.load()
    available = image.width * image.height * 3
    size = len(message)
    print("available:", available)
    print("size:", size)
    if available <= size * 8 + 8 * len(b"\x90\xbfhttps://github.com/evil-steganography/evil-stego-1"):
        raise NotEnoughValuesException("Needs {:d} bits worth of space, only got {:d}" \
                                       .format(
            size * 8 + 8 * len(b"\x90\xbfhttps://github.com/evil-steganography/evil-stego-1"), available))

    seed = [random.getrandbits(8) for i in range(4)]
    random.seed(bytes(seed))
    print(len(bytes(seed)))
    print(seed)

    valid_spots = []
    for channel in range(3):
        for y in range(image.height):
            for x in range(image.width):
                valid_spots.append((x, y, channel))

    metadata = b"\x90\xbfhttps://github.com/evil-steganography/evil-stego-1" + bytes(seed) + pack("<I", size)
    c = 0
    for byte in metadata:
        write_byte(pixels, byte, valid_spots[c:c + 8])
        c += 8

    locations = random.sample(valid_spots[c:], size * 8 + 1)
    c = 0
    for byte in message:
        write_byte(pixels, byte, locations[c:c + 8])
        c += 8
    return image


def read_bit(pixels, location: Tuple[int, int, int]) -> int:
    x, y, channel = location
    orig = list(pixels[x, y])
    return int(orig[channel] & 1)


def read_byte(pixels, locations: List[Tuple[int, int, int]]):
    bits = []
    for i in range(8):
        bits.append(read_bit(pixels, locations[i]))
    print(bits)
    byte = 0
    for bit in bits:
        byte <<= 1
        byte += bit
    return byte


def decode(image: Image, seed: list, size):
    image = image.convert("RGB")
    pixels = image.load()

    random.seed(bytes(seed))

    valid_spots = []
    for channel in range(3):
        for y in range(image.height):
            for x in range(image.width):
                valid_spots.append((x, y, channel))

    metadata = b"\x90\xbfhttps://github.com/evil-steganography/evil-stego-1" + bytes(seed) + pack("<I", size)
    c = 0
    for byte in metadata:
        print(byte)
        read = read_byte(pixels, valid_spots[c:c + 8])
        assert byte == read, f"{byte} {read}"
        c += 8

    locations = random.sample(valid_spots[c:], size * 8 + 1)
    c = 0
    read_bytes = bytearray()
    for _ in range(size):
        read_bytes.append(read_byte(pixels, locations[c:c + 8]))
        c += 8
    return read_bytes


if __name__ == "__main__":
    # from argparse import ArgumentParser
    # parser = ArgumentParser()
    # enc_group = parser.add_mutually_exclusive_group(required=True)
    # enc_group.add_argument("--encode", dest="enc", action="store_true",
    #     help="Encode message. Requires message if used.")
    # parser.add_argument("filename", action="store",
    #     help="File to use in steganography.")
    # parser.add_argument("-o", "--outfile", dest="outfile", default=None, action="store",
    #     help="File to write to. Defaults to original file.")
    # parser.add_argument("-m", "--message", dest="msg", default=None, action="store",
    #     help="Message to write. If omitted in encode mode, will read from stdin.")
    #
    # args = parser.parse_args()
    #
    # if args.msg is None:
    #     args.msg = ""
    #     while True:
    #         try:
    #             a = input()
    #             args.msg += a + "\n"
    #         except EOFError:
    #             break
    # with Image.open(args.filename) as image:
    #     res = encode(image, bytes(args.msg, "ascii"))

    seed = [0xed, 0xfe, 0xcb, 0x10]
    print(seed)
    print(unpack("<I", b"\x22\x00\x00\x00"))
    with Image.open("evil.png") as image:
        #     res = encode(image, bytes("test", "ascii"))
        print(decode(image, [237, 254, 203, 16], 34))
    # res.save(args.filename if args.outfile is None else args.outfile)
