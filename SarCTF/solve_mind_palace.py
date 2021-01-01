from pwn import *

from utils.morseCode import from_morse_code

rem = remote("212.47.229.1", 33001)


def repeated(decoded) -> bool:
    if len(decoded) % 2 != 0 or len(decoded) < 4:
        return False

    return decoded[len(decoded)//2:] == decoded[:len(decoded)//2]


def solve() -> None:
    decoded = ""
    cur = ""
    while repeated(decoded) is False:
        rec = rem.recv().decode().strip('\r').strip(' ')
        print(rec)
        if rec == 'piiiip':
            cur += '-'
        elif rec == 'pip':
            cur += '.'
        elif len(cur) > 0:
            decoded += from_morse_code(cur)
            print(decoded)
            cur = ""
        elif decoded[-1] != ' ':
            decoded += ' '



if __name__ == "__main__":
    solve()