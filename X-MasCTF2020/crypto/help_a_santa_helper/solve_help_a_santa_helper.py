from binascii import hexlify, unhexlify
from pwn import remote
from utils.hashes.finder import get_sha256_tail


def main():
    r = remote("challs.xmas.htsp.ro", 1004)

    PoW = r.recvline().decode().strip().split()[-1]
    ans = get_sha256_tail(PoW)
    print(PoW, ans)
    r.sendline(hexlify(ans.encode()))

    print(r.recvuntil("exit\n\n").decode().strip())

    r.sendline('1')
    print('1')
    print(r.recvuntil("message.\n").decode().strip())

    m1 = hexlify(b'\x00' * 16)
    r.sendline(m1)
    print(m1)
    line = r.recvline().decode().strip()
    print(line)
    digest = line.split()[-1].strip('b').strip('.').strip("'")
    print("digest:", digest)
    print(r.recvuntil("exit\n\n").decode().strip())

    r.sendline('2')
    print('2')
    m2 = hexlify(b'\x00' * 16 + unhexlify(digest)).decode()
    r.sendline(m2)
    print(m2)

    m3 = hexlify(b'').decode()
    r.sendline(m3)
    print(m3)

    print(r.recvall(3).decode().strip())


if __name__ == '__main__':
    main()


def test():
    import os
    from Crypto.Cipher import AES
    from binascii import hexlify


    def xor(a, b):
        return bytes([x ^ y for x, y in zip(a, b)])


    def pad(msg, block_size):
        if len(msg) % block_size == 0:
            return msg
        return msg + bytes(block_size - len(msg) % block_size)


    class Hash:
        def __init__(self, seed=None):
            if seed == None:
                seed = os.urandom(16)

            self.perm = AES.new(seed, AES.MODE_ECB)
            self.get_elem = self.perm.encrypt
            self.hash = bytes(16)
            self.string = b""

        def update(self, msg):
            msg = pad(msg, 16)
            for i in range(0, len(msg), 16):
                self.string += msg[i:i + 16]
                self.hash = xor(msg[i:i + 16], self.get_elem(xor(self.hash, msg[i:i + 16])))

        def digest(self):
            return self.hash

        def hexdigest(self):
            return hexlify(self.digest())


    # seed = os.urandom(16)
    # print(seed)
    seed = b'$\xf4\xbf\xe8\x01*a\x9f\xed\xef\x05\xdb./\xd7\xb3'
    t = Hash(seed)
    t1 = Hash(seed)
    t2 = Hash(seed)
    t.update(b'\x00' * 16)
    t1.update(b'\x00' * 16 + t.digest())
    t2.update(b'')
    print(t.string, t.digest())
    print(t1.string, t1.digest())
    print(t2.string, t2.digest())
