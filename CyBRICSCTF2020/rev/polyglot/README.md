# CyBRICS 2020 Baby Rev Keyshooter Writeup
by qpwoeirut

Category: Reverse<br>
Difficulty: Easy<br>
Points: 50
> Author: Egor Zaytsev (@groke)
>
> Prove us that you are a real polyglot :)
>
> Download: polyglot.tar.gz

We get a program written in C and need to reverse it and some other programs it will print.

## TL;DR
Rev the C program and run it to get a C++ program.
Do it again to get a Python program.
Use uncompyle6 to reverse the Python bytecode and get the flag.

## Explanation
We start with a `code.c` program.
It uses an environment variable as a key for xor, but it also does a `strncmp` with the constant string "mod3r0d!", so we can just set the key instead of using an environment variable.

Running this program gets us `part2.cpp`.
Trying to run the program without edits gets a recursion depth exceeded for template error.
But if we analyze the template all it's doing is multiplication and addition.
So we can rewrite the templates to be much more efficient.

This gets us `part3.py`.
It creates a bunch of functions using bytecode through `CodeType`.
We can get the decompiled version by using `uncompyle6.deparse_code`.
Once we have that it's pretty clear that the functions just compare input to a constant array.
We can take that array, convert to chars, and get the flag.

`cybrics{4abd3e74e9e5960a1b6b923d842ccdac13658b3f}`