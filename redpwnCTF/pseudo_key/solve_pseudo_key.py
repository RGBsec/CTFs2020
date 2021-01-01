from string import ascii_lowercase

chr_to_num = {c: i for i, c in enumerate(ascii_lowercase)}  # a mapping of a->0, b->1, c->2, etc.
num_to_chr = {i: c for i, c in enumerate(ascii_lowercase)}  # a mapping of 0->a, 1->b, 2->c, etc.


def encrypt(ptxt, key):
    ptxt = ptxt.lower()
    key = ''.join(key[i % len(key)] for i in range(len(ptxt))).lower()  # cycle the key to the length of the plaintext
    ctxt = ''
    for i in range(len(ptxt)):
        if ptxt[i] == '_':  # this encryption ignores underscores
            ctxt += '_'
            continue
        x = chr_to_num[ptxt[i]]  # convert the characters to numbers
        y = chr_to_num[key[i]]
        ctxt += num_to_chr[(x + y) % 26]  # add the numbers together, mod 26, and convert back to character
    return ctxt


pk = "iigesssaemk"
# print the options for the key
for c in pk:
    print(chr_to_num[c], num_to_chr[chr_to_num[c] // 2], num_to_chr[chr_to_num[c] // 2 + 13])

key = "redpwwwnpts"
# this key makes the most sense, and it would create the correct encrypted key
assert encrypt(key, key) == pk

ct = "z_jjaoo_rljlhr_gauf_twv_shaqzb_ljtyut"
# do the same thing as encrypt, but subtract instead
key = ''.join(key[i % len(key)] for i in range(len(ct))).lower()
out = ''
for i in range(len(ct)):
    if ct[i] == '_':
        out += '_'
        continue
    x = chr_to_num[ct[i]]
    y = chr_to_num[key[i]]
    out += num_to_chr[(x - y + 26) % 26]  # undo the encryption

print(out)
