# CSICTF 2020 AKA Writeup
by qpwoeirut

Category: Linux<br>
Points: 100

> Cows are following me everywhere I go. Help, I'm trapped!<br>
> `nc chall.csivit.com 30611`

## Explanation
If we try running any commands we just get an ascii art cow.
It seems all of the commands have been changed, but we can easily get around this by using absolute path.

`/bin/ls` will list the files and we see `flag.txt` is one of them. To get the flag we run `/bin/cat flag.txt`.

`csictf{1_4m_cl4rk3_k3nt}`