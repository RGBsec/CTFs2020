# H@cktivityCon CTF 2020 Perfect XOR Writeup
by qpwoeirut

Category: Crypto<br>
Points: 100<br>
> Can you decrypt the flag?
>
> Download the file below.

Files: decrypt.py

## Explanation
The base64 string decodes into a list of numbers, which are then XORed with a number if it passes a certain check.
When we look at function `a`, we see that it checks if the sum of the divisors of `n` is equal to `n`.
If we search that phrase, we get a bunch of articles on "perfect numbers".
From here we can find a list of the first 14 perfect numbers and xor them with the encrypted flag.

The list I used was from https://web.archive.org/web/20090503154707/http://amicable.homepage.dk/perfect.htm

Implementation of decryption at `solve_perfect_xor.py`.

`flag{tHE_br0kEN_Xor}`

