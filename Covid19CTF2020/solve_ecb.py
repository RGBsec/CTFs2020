from string import printable
from time import sleep

from pwn import remote


r = remote("10.2.202.52", 8000)

BLOCK_SIZE = 16


def to_blocks(s: str) -> list:
    return [s[n:n + BLOCK_SIZE + BLOCK_SIZE] for n in range(0, len(s), BLOCK_SIZE + BLOCK_SIZE)]


def com(s: bytes):
    # print("sending:", s)
    r.recvuntil("What do you want to encrypt?\n")
    r.sendline(s)
    res = r.recvline().decode()
    ret = res.split(':')[1].strip()
    # print(ret)
    return ret


def main():
    known = b"derp{3cb_may_n0t_b3_7he_b3st_4ft4r_ALL}"
    # known = b''

    # known_block = (b'\x00' * (BLOCK_SIZE))
    known_block = known[-16:]
    for block in range(2,6):
        # guess = (b'\x00' * (BLOCK_SIZE - 1))
        guess = known_block[1:]
        print("block:", block)
        known_block = b''
        for _ in range(BLOCK_SIZE):
            print("guess:", guess)
            enc = com(guess)
            print("enc:  ", enc)
            enc_block = to_blocks(enc)[block]

            for c in printable:
                guess_enc = com(guess + known_block + c.encode())
                # print("g-enc:", guess_enc)
                # print(to_blocks(guess_enc)[block])
                # print(enc_block)
                if to_blocks(guess_enc)[0] == enc_block:
                    print("found next:", c)
                    known_block += c.encode()
                    break

            guess = guess[1:]
            sleep(2)

        known += known_block

    print(known)


if __name__ == "__main__":
    main()
