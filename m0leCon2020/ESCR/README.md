m0leCon CTF 2020 Writeups: ESCR

Category: Crypto
Points: TBD

> Eat, Split, Compress, Repeat.<br>
> `nc challs.ctf.m0lecon.it 8001`<br>
> Author: @mr96

## Explanation
I solved this with the same (probably unintended) method as babyhash.
Since we're given the original string before it's hashed, we can add a null byte at the start, which `bytes_to_long` will ignore.
Our input is only used in that spot (because it gets converted using `bytes_to_long`), so we will get the same hash.

`ptm{never_trust_dummy_hashes}`