# CSICTF 2020 Find32 Writeup
by qpwoeirut

Logging in gets us a bunch of files full of random uppercase letters.
To get the flag, I assumed it would have underscores.
So we can run `grep -r "_" .` to search for underscores in all the files.
This gets us a fake flag, but right next to it we see the credentials for user2.

If we take those credentials and then grep for "_" again, we find the flag.

`csictf{th15_15_unu5u41}`

In hindsight, I probably should have searched for "{" or "}" since those are guaranteed to be in the flag.