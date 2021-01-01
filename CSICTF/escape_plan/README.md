# CSICTF 2020 Escape Plan Writeup
by qpwoeirut

Category: Misc<br>
Points: 469

> I found a script that solves ciphers, they say it's pretty secure!
>
> `nc chall.csivit.com 30419`

## Explanation
Escaping the pyjail is pretty easy, since imports aren't disabled.
Something like `__builtins__.__import__("os").system()` would work.
But we don't actually need to get an RCE.

The description that the server prints mentions it's open source.
We can get the source code and just search it.
To get source code, we can `print(__builtins__)` to tell us the name of the file.
Then we can `print(open("crypto.py").read())` to get the file source.

If we copy-paste the first function into a search engine we get a [GitHub file](https://github.com/alias-rahil/crypto-cli/blob/21c14711539895c717dd14c6dbb234d590cf154c/crypto.py).
Then if we poke around in commits we see an interesting commit message: `fix: oops xD`.
Looking at the diff of that will get us the flag.

`csictf{2077m4y32_h45_35c4p3d}`