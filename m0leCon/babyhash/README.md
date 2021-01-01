# m0leCon CTF 2020 Writeups: babyhash

Category: Crypto
Points: TBD

> Oh no! I've accidentally blacklisted my admin credentials, can you help me to find a way to break in?<br>
> `nc challs.ctf.m0lecon.it 8000`<br>
> Author: @matpro


## Explanation
We get a python file and an nc server.
I was able to cheese this challenge by simply circumventing the check for whether we'd entered "admin" and "password".
Since it checks using equality, we can just add a null byte to the beginning of both the username and password.
Both the username and password are just used in `bytes_to_long`, which uses big endian.
This will remove the null byte's value and we have "admin" and "password".

Our final creds are just `0061646d696e` and `0070617373776f7264`, which are the `hexlify`-ed versions of `\x00admin` and `\x00password`.

`ptm{a_b1g_s0phi3_germ41n_pr1m3}`