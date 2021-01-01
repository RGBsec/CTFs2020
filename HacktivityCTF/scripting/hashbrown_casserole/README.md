# H@cktivityCon CTF 2020 Hashbrown Casserole Writeup
by qpwoeirut

Category: Scripting<br>
Points: 150<br>

> Hashbrowns
>
> Connect here:
> nc jh2i.com 50005

For this challenge I decided to generate a rainbow table of hashes for use in the future as well.
It took 3 hours to generate 36^5 hashes with python.
Then I write a binary search to search the hashes.

`flag{warm_casseroles_for_breakfast!!!}`