from ast import literal_eval
from functools import reduce
from pwn import remote
from sympy import mod_inverse


# given a list of mods and remainders, find the original number modulo the product of all mods
def chinese_remainder(mods, remainders):
    total = 0
    prod = reduce(lambda x, y: x * y, mods)
    for mod, remainder in zip(mods, remainders):
        p = prod // mod
        total += remainder * mod_inverse(p, mod) * p
    return total % prod, prod


def main():
    rem = remote("chal.uiuc.tf", 2004)
    rem.recvuntil("How many coelacanth have you caught? ")
    rem.sendline('9')

    for lock in range(5):
        rem.recvuntil("Here are your key portions:\n")
        shares = literal_eval(rem.recvline(keepends=False).decode())  # parse the list the server sends
        print(shares)
        x, y = chinese_remainder([t[1] for t in shares], [t[0] for t in shares])
        print(lock, x, y)
        for mult in range(250):  # try adding the final mod until we find the right answer
            rem.recvuntil("Please input the key: ")
            rem.sendline(str(x + y * mult))
            if b"unlocked" in rem.recvline():
                print("Answer: ", x + y * mult)
                break

    print(rem.recvall(2).decode())


if __name__ == '__main__':
    main()
