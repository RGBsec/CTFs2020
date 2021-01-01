# H@cktivityCon CTF 2020 Tyrannosaurus Rex Writeup
by qpwoeirut

Category: Crypto<br>
Points: 200<br>

Files: ofbuscated.py

`ofbuscated.py` encrypts the flag by doing AES encryption on an IV and then xoring it with the flag.
The flag is split into blocks and shuffled beforehand.

## Explanation
`ofbuscated.py` runs `assert len(flag) % 16 == 1`, which gives us one of the plaintext blocks.
We know the last character of the flag is "}", and so we have one of the 3 blocks of plaintext.
With this information we can recover the other blocks.

Since the flag blocks are shuffled before encryption, we can collect all the different encrypted permutations of blocks.
In each one, the first, second, or third block will be our known block.
So we can calculate all possible keys for that block, and see which ones decrypt to readable plaintext.

Implementation at `solve_ofbuscated.py`.

`flag{bop_it_twist_it_pull_it_lol}`