from pwn import remote


# send a query with i = n-1 and j = n
def get_bits(n) -> str:
    r = remote("2020.redpwnc.tf", 31284)
    assert r.recv().decode().strip() == "Enter an integer i such that i > 0:"
    r.sendline(str(n - 1))
    assert r.recv().decode().strip() == "Enter an integer j such that j > i > 0:"
    r.sendline(str(n))
    return r.recvline().decode().split(':')[1].strip()


def main():
    ct = ['0'] * 301
    done = [False] * 301
    done[0] = True
    done[1] = True
    for i in range(2, len(ct)):
        # send every prime number and get the entire plaintext
        if not done[i]:
            print(i)
            bits = get_bits(i)
            for j in range(i, len(ct), i):
                ct[j] = bits[j]
                done[j] = True

    ct = ''.join(['0' if c == '1' else '1' for c in ct])
    # flip all the bits since everything was xored
    print(ct)

    flag = ''
    cur = 0
    for bit in ct:
        cur <<= 1
        cur += int(bit)
        if 2 ** 6 <= cur < 2 ** 7:
            # we know from source that every character is between 2^6 and 2^7
            flag += chr(cur)
            cur = 0
    print(flag)


if __name__ == '__main__':
    main()
