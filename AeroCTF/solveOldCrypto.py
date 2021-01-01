from base64 import b64decode
from pwn import remote, context, logging
from string import hexdigits
from time import sleep

context.log_level = logging.WARNING
BLOCK_SIZE = 16


def to_blocks(s: str) -> list:
    return [s[n:n + BLOCK_SIZE] for n in range(0, len(s), BLOCK_SIZE)]


def interact(chosen):
    try:
        rem = remote("tasks.aeroctf.com", 44323)
        rem.recvuntil('>')
        rem.sendline(b'3')
        rem.sendline(chosen.decode())
        resp = rem.recvline().decode()
        resp = resp.split(": b'")[1].strip().strip("'")
        resp = b64decode(resp)

        # print(resp)
        print(chosen.decode())
        blocks = to_blocks(resp)
        return blocks
    except EOFError:
        return interact(chosen)


def main():
    guessed_secret = ""

    PADDING = bytearray(b'\x00' * BLOCK_SIZE)
    chosen = PADDING + bytearray(('\x11'*8).encode())

    blocks = interact(chosen)
    for _ in range(16):
        print(blocks)
        if blocks[0] == blocks[-1]:
            break
        chosen.append(ord('\x11'))
        blocks = interact(chosen)

    print("Found length")

    for _ in range(40):
        chosen.insert(0, 0xFF)
        for guess in hexdigits + "{}_roRO":
            chosen[0] = ord(guess)

            blocks = interact(chosen)
            print(blocks[0], blocks[4], '\n')

            if blocks[0] == blocks[4]:
                guessed_secret = guess + guessed_secret
                print("guessed_secret:", guessed_secret)
                break
        else:
            print("Final secret:", guessed_secret)
            break


if __name__ == "__main__":
    main()
