# NACTF 2020 Writeups: Random Number Generator
Points: 250

> Dr. J created a fast pseudorandom number generator (prng) to randomly assign pairs for the upcoming group test. Austin really wants to know the pairs ahead of time... can you help him and predict the next output of Dr. J's prng?<br><br>
> `nc challenges.ctfd.io 30264`

Hint:
> Check out "Dr. J's Vegetable Factory #1 🥕" to see an example of how to connect to the server with code.

## Explanation
We know the that the PRNG seeds the with the time, but we don't know the precise time.
To get around this we can just try all the recent times until one of them matches.

`nactf{ch000nky_turn1ps_1674973}`