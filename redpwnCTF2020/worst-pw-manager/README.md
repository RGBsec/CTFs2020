# redpwnCTF 2020 Worst Password Manager Writeup
by qpwoeirut

Category: Crypto<br>
Points: 482

> I found this in-progress password manager on a dead company's website. Seems neat.

The first thing we can immediately see is that the passwords are not secure at all since they're used to name the file.
The only encryption is that each character is rotated.
Once reverse a rather hideous list comprehension we can get the passwords.

So now it looks like we need to recover the master password, which is used in the RC4 encryption.
I spent a bunch of time at this point researching (by which I mean searching Google and reading StackOverflow) ways to recover RC4 keys.
I didn't find anything, so I started just messing around and realized that each `KeyByteHolder` actually holds the same byte, due to some random python behavior I don't fully understand.
Once we know this, it's easy to brute force different bytes of the key as it wraps around.
Fortunately the key is coprime to 8, so we can recover the flag. Implementation at `solve_pw_manager.py`.