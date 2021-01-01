# redpwnCTF 2020 base646464 Writeup
by qpwoeirut

Category: Crypto<br>
Points: 145

> Encoding something multiple times makes it exponentially more secure!

As the challenge title hints, this is repeated base64 encoding.
The provided JavaScript file shows that the flag has been base 64 encoded 25 times.
To solve, we can just continuously decode and print the current text.
This program will eventually crash but we get the flag.
Implementation at `solve_base646464.py`