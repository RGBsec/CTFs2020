# X-Mas CTF 2020 Writeups: Santa's public key factory

Category: Crypto<br>
Points: 226

> Santa wanted this factory built ASAP, but we think he got a bit careless and didn't take everything into consideration when it comes to security.
Take a look for yourself, maybe you find something.<br>
> Target: nc challs.xmas.htsp.ro 1000<br>
> Author: Gabies

## Explanation
There's only 2<sup>16</sup> different possible primes that each instance of `chall` can generate.
If we ask for 255 public keys (which is our maximum since we need one chance to guess), that means that 510 primes of those 2<sup>16</sup> primes will be chosen.
We want a prime to be chosen twice, so that we can get `p = gcd(n, n')` where `n` and `n'` share a prime.
That gets us `p`, which is enough to decrypt the secret message.

There are (2<sup>16</sup>)<sup><sup>510</sup></sup> total ways that the primes can be chosen.
(2<sup>16</sup>)! -(2<sup>16</sup> - 510)! of them will have only distinct primes with no repeats, which is not what we want.
So that means we can subtract the "bad" ways from our total, and then divide that value to get the chance any prime will get chosen multiple times.
This gets us around a 86.27% chance of success for each connection we open to the server.

`X-MAS{M4yb3_50m3__m0re_r4nd0mn3s5_w0u1d_b3_n1ce_eb0b0506}`