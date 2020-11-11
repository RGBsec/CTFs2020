from binascii import unhexlify
from pwn import remote, process
from utils.flag_strings import leet_flag_chars

r = remote("chal.ctf.b01lers.com", 2007)
# r = process(["python3", "spinningtop-dbf4f2d58c98c017aee7b63bc5da323b.py"])

def query(pt: bytes) -> str:
    r.sendline(pt)
    resp = r.recvline().strip()
    if resp == b"True":
        print("FLAG:", pt)
        print(int(pt[2:], 2).to_bytes(20, 'big'))
        exit(0)
    elif resp == b'False':
        raise Exception("Maximum number of tries exceeded")
    return unhexlify(resp).decode()


def main():
    len_check = query(b'a' * 1024)
    ct_len = len(len_check)
    assert ct_len % 16 == 0, ct_len

    print("ct_len:", ct_len)

    bin_flag = b"0b1100110011011000110000101100111"
    # progress:  0b11001100110110001100001011001110111101101100010
    # progress:  0b110011001101100011000010110011101111011011000100111001001010101
    # progress:  0b1100110011011000110000101100111011110110110001001110010010101010111010000110011
    # progress:  0b11001100110110001100001011001110111101101100010011100100101010101110100001100110101111100110100
    # progress:  0b110011001101100011000010110011101111011011000100111001001010101011101000011001101011111001101000110010101110110
    # progress:  0b11001100110110001100001011001110111101101100010
    # test flag: 0b1100110011011000110000101100111011110110110000101100110011000010110101101100101010111110110011001101100011000010110011101111101
    assert set(query(bin_flag)) == set('\x00'), query(bin_flag)

    while True:
        for c1 in leet_flag_chars:
            print(c1)
            ok = False
            bin1 = bin(ord(c1))[2:].rjust(8, '0').encode()
            for c2 in leet_flag_chars:
                bin2 = bin(ord(c2))[2:].rjust(8, '0').encode()
                if query(bin_flag + bin1 + bin2).endswith('\x00' * 8):
                    bin_flag += bin1 + bin2
                    print(bin_flag)
                    ok = True
                    break
            if ok:
                break


if __name__ == '__main__':
    main()