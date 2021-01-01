# redpwnCTF 2020 Itsy-Bitsy Writeup
by qpwoeirut

Category: Crypto<br>
Points: 436

> The itsy-bitsy spider climbed up the water spout...
>
> `nc 2020.redpwnc.tf 31284`

This challenge had a nc server and its source.
It looks like some sort of one-time pad, but we can game the random number generator to find the plaintext.
We can send i = n-1 and j = n, and then we know that every nth bit will be set in the random number.
From here we can leak bits of the plaintext, and get the flag.
We only need to send every prime number since that will cover everything.
Implementation at `solve_itsy_bitsy.py`.