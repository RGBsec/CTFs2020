# UIUCTF 2020 Coelacanth Vault Writeup
by qpwoeirut

Category: Crypto<br>
Points: 300<br>
Description:<br>
> Why would you waste your time catching more than one coelacanth?
>
> `nc chal.uiuc.tf 2004`
>
> Author: potatoboy69

Files: coelacanth_vault.py

## Explanation
We're given an nc server and its source.
Analyzing the script shows that we need to solve 5 "locks" to get the flag.

For each lock, the script calls `create_key`, which generates a list of random primes.
Then it calculates the product of the first 10 primes and the product of the last 5, and generates a random number between them.
It also creates a list of the random number mod each prime.

The random number is the secret, and the list of modular residues is the shares.
After generating the secret and shares the program checks that the key is valid, but this doesn't really matter to us.
We can choose how many shares are given to us, as long as it's not more than 9.
So obviously we should ask for 9 shares, since more information is better.
Then we have 250 tries to guess the secret.

## Solution
We can solve this using Chinese Remainder Theorem.
Since we have the secret mod some primes, we can calculate the secret mod the product of the primes.
But we're not given every prime, so we need to do some brute forcing.
It suffices to add the mod over and over again until we find the right answer.

For an implementation see `solve_coelacanth.py`.

` uiuctf{small_oysters_expire_quick}`