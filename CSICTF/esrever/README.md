# CSICTF 2020 Esrever Writeup
by qpwoeirut

Category: Reversing<br>
Points: 493

> I encrypted my flag so that nobody can see it, but now I realize I don't know how to decrypt it. Can you help me?

Files: esrever.py, esrever.txt

## Explanation
The reversing isn't actually that bad - you just need to make one observation about `enc1` and the rest is straightforward.
`enc2`, `enc3`, and `enc4` can all be easily reverse by just doing everything backwards with inverses.

When we look at `enc1` it's really just a caesar cipher, no matter how many times you run it.
Since the shift is the same for every character, and it wraps around, we can just brute force all 26 different shifts.

We can write the inverses of `enc2`, `enc3`, and `enc4` and then just check every shift of the result.
The one with the flag format will be our flag.

Also, make sure you call your decrypts in order.
I spent 20 minutes wondering if I'd messed up my reversal of `enc1` before realizing I'd called `rev2` and `rev3` in the wrong order.

Implementation of the decryption program at `solve_esrever.py`.

Note about the script: As far as I can tell, `enc1` could be written without the `bytes.fromhex`:
```
def better_enc1(text):
    r = random.randint(1, 25)
    return ''.join([chr(((ord(i) - ord('a') - r) % 26) + ord('a')) for i in text])
```

`csictfaesreverisjustreverseinreverserightc`
`csictf{esreverisjustreverseinreverseright}`