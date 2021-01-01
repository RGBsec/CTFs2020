# H@cktivityCon CTF 2020 Misdirection Writeup
by qpwoeirut

Category: Scripting<br>
Points: 125<br>

> Check out the new Flag Finder service! We will find the flag for you!
>
> Connect here:
> http://jh2i.com:50011/

Autoindexing is on, so we can enumerate through each file.
Some files will say "character x of the flag is y".
We can put those together and get the flag.

Implementation at `solve_misdirection.py`.

`flag{http_302_point_you_in_the_right_redirection}`