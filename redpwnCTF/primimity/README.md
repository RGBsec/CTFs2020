# redpwnCTF Primimity Writeup
by qpwoeirut

Category: Crypto<br>
Points: 450

> People claim that RSA with two 1024-bit primes is secure. But I trust no one. That's why I use three 1024-bit primes.
> 
> I even created my own prime generator to be extra cautious!

We are given an RSA public key and RSA implementation.
My teammate basically solved the challenge in a minute, and I implemented the solution.
The 3 random primes generated are based on each other, so they are all very close together.

We can use `sympy.prevprime` and `sympy.nextprime` to find the primes.
Since there are 3 primes, we can start from the cube root of n.
Once we have the primes, it's trivial to get the private exponent and the flag.
Implementation at `solve_primimity.py`.