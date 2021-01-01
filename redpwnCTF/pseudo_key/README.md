# redpwnCTF 2020 Pseudo-key Writeup
by qpwoeirut

Category: Crypto
Points: 341

> Keys are not always as they seem...

> **Note**: Make sure to wrap the plaintext with flag{} before you submit!

We're given a pseudo-key.py and its output.
It looks like the encryption just rotates the plaintext by the key.
We are given the encrypted flag, and the encrypted key.
We can attack the key first, since it's each char times 2 mod 26.


So to reverse it, each character is either itself divided by 2, or itself divided by 2 plus 13 because of the mod.
If we do this, and print out both options, we see that there's a somewhat understandable key: `redpwwwnpts`.
Then we can reverse the encryption by subtracting the key from the ciphertext.
Our key doesn't actually get the correct flag, but it's close enough that we can correct the mistakes.
Implementation at `solve_pseudo_key.py`.
