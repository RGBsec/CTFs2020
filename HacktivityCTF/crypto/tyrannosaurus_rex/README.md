# H@cktivityCon CTF 2020 Tyrannosaurus Rex Writeup
by qpwoeirut

Category: Crypto<br>
Points: 100<br>

> We found this fossil. Can you reverse time and bring this back to life?
>
> Download the file below.

Files: fossil

## Explanation
Opening `fossil` reveals that it's a python program.
All the encryption does is xor adjacent bytes.
We can easily brute force the first byte and then calculate the others.

Implementation at `solve_t_rex.py`.

Flag is misspelled?<br>
`flag{tyrannosauras_xor_in_reverse}`