from math import log2, sqrt

from sympy import isprime, randprime, prevprime, nextprime


# from utils.rsa_util import *
#
#
# hn = "aa0d98fab0246c18f7c411b09419d49d4bcf001686262a9fcf3e65d73deb58b876dfa4079eb65c6dc5c2bf34d1c3d5284db316cd4b7a02f7d43dbebf2e56a867db159a11af5d8877e906df7a3208e7cc9a9ab89cfb7556a503667e432c582aac852e3df442c70f57941b7745e1b0cf88f21498707d1e482a3742e3917488949"
hn = "7ef80c5df74e6fecf7031e1f00fbbb74c16dfebe9f6ecd29091d51cac41e30465777f5e3f1f291ea82256a72276db682b539e463a6d9111cf6e2f61e50a9280ca506a0803d2a911914a385ac6079b7c6ec58d6c19248c894e67faddf96a8b88b365f16e7cc4bc6e2b4389fa7555706ab4119199ec20e9928f75393c5dc386c65"
# n = int(hn, 16)
# ciphertext = int("3ea5b2827eaabaec8e6e1d62c6bb3338f537e36d5fd94e5258577e3a729e071aa745195c9c3e88cb8b46d29614cb83414ac7bf59574e55c280276ba1645fdcabb7839cdac4d352c5d2637d3a46b5ee3c0dec7d0402404aa13525719292f65a451452328ccbd8a0b3412ab738191c1f3118206b36692b980abe092486edc38488", 16)
#

ans = []
hexdigits = "fedcba9876543210"


def rec(p: str, q: str):
    if p.startswith('000') or q.startswith('000'):
        return
    L = len(p)
    if L >= 128:
        if p[0] != '0' and q[0] != '0':
            with open("rsa_ans.txt", 'a+') as ans_file:
                ans_file.write(f"{p}\n{q}\n\n")
            ans.append((p,q))
            print(p)
            print(q)
            print()
        return
    if L >= 110:
        print(f"{p}\n{q}\n\n")
    for i in hexdigits:
        np = f"{i}{p}"
        ip = int(np, 16)
        nrp = np[::-1]
        irp = int(nrp, 16)
        for j in hexdigits:
            nq = f"{j}{q}"
            iq = int(nq, 16)
            nrq = nq[::-1]
            irq = int(nrq, 16)
            product = hex(ip*iq)[2:]
            rprod = hex(irp*irq)[2:]
            if hn.endswith(product[L+1:]) and hn.startswith(rprod[:L-1]):
                rec(np, nq)


rec("", "")
print(ans)
print(len(ans))
# for tp in ans:
#     print(hex(int(tp[0],16) * int(tp[1],16)))

# fef213a936206a4bbc044b49aeee5dcc27b4b8faaa6ed3ee4ed82f7f2dbb7fe86e89fa5626a104580e65713370febafe8b8f45f1e5079bde0f24c546541b3e0d
#                   1001338f7d12a9e57c24adc3e8929cd8f462f9816371c9d5b1965626a104580e65713370febafe8b8f45f1e5079bde0f24c546541b3e0d