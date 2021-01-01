# this only works on OpenSSL, not LibreSSL
#

from subprocess import Popen, PIPE

key_opts = ['m', 'a', 'h', 'c', 'hn', 'lkop', 'u', 'd', 'q', 'lkop', 'rt', 'lkop', 'za', 'e', 'er', 'b']
print(len(key_opts))
print(key_opts)

with open("flag.txt.enc", 'rb') as f:
    flag = f.read()[16:]
print(flag)


flags = []
def solve(key):
    if len(key) == len(key_opts):
        proc = Popen(["openssl", "enc", "-d", "-aes-256-cbc", "-in", "flag.txt.enc", "-k", key], stdout=PIPE)
        dec = proc.stdout.read()
        if b"cybric" in dec.lower():
            flags.append((key, dec))
        return

    idx = len(key)
    for opt in key_opts[idx]:
        solve(key + opt.encode())


solve(b'')
print(flags)
