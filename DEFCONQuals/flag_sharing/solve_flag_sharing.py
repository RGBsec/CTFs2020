import ast
from pwn import remote, process

from DEFCONQuals2020.flag_sharing.matrix_inverse import getMatrixInverse, P


def main():
    K = 5
    # r = remote("ooo-flag-sharing.challenges.ooo", 5000)
    r = process(["./chal.py"])
    r.recvuntil("Username:")
    r.sendline("qpwoeirut")

    inv_int = []
    for share in range(K):
        inv_int.append([])
        for idx in range(K):
            r.recvuntil("Choice:")
            r.sendline('2')
            r.sendline("0cc175")  # md5 hash tail/ID
            # a: 0cc175
            # b: 92eb5f
            r.recvuntil(b"secret: ")
            shares = [(share, 0), (96, 0), (97, 0), (98, 0), (99, 0)]
            shares[idx] = (shares[idx][0], 1)
            shares = str(shares)
            print(shares)
            r.sendline(shares)
            resp = r.recvline().decode()
            if "ERROR" in resp:
                print(resp)
                break
            resp = resp.split(':', maxsplit=1)[1].strip()

            key: bytes = ast.literal_eval(resp)
            print(key)

            inv_int[share].append(int.from_bytes(key, 'little'))

    def prlst(lst):
        for r in lst:
            print(r)
    prlst(inv_int)

    ############################################################################
    # EVERYTHING BELOW ONLY WORKS IF inv_int is the full inverse matrix, mod P #
    ############################################################################
    # inv_det = getMatrixDeternminant(inv_int) % P
    # inv_inv = getMatrixInverse(inv_int)
    # for row in inv_inv:
    #     print(row)
    # inv_inv_int = [[int(round(inv_det * inv_inv[row][i])) * pow(inv_det, -1, P) % P for i in range(K)] for row in range(K)]
    # for row in inv_inv_int:
    #     print(row)


    ###########
    # TESTING #
    ###########
    print('\n' * 5)
    M = ast.literal_eval(open("matrix.ooo").read().strip())
    M = [M[0]] + M[96:]
    print(M)
    prlst(getMatrixInverse(M))


if __name__ == '__main__':
    main()
