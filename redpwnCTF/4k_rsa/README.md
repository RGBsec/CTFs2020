# redpwnCTF 2020 4k RSA Writeup
by qpwoeirut

Category: Crypto<br>
Points: 389

> Only n00bz use 2048-bit RSA. True gamers use keys that are at least 4k bits long, no matter how many primes it takes...

All we get is a public RSA key and encrypted message.
But the description hints that the modulus has many prime factors.
Originally I tried sympy.factorint but it took too long.
One of my teammates suggested Alpertron, which factored the modulus in about 20 minutes.
From there, we can calculate phi(n) and then find the secret exponent.
See `solve_4k_rsa` for implementation. The utils are basic stuff that should be self-explanatory.