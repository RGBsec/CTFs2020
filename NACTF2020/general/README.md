# NACTF 2020 Writeups: Join the Discord, Intro to Flags, Basics, Grep 0, Numbers, Hashbrowns, Arithmetic

## Join the Discord
Points: 10
> Join the NACTF 2020 [Discord](https://discord.gg/c3ndsa4) and find the flag!<br>
> -mcantillon

Check #welcome: `nactf{n1c3_j0b_h4v3_fun}`


## Intro to Flags
Points: 10
> NACTF flags are case-sensitive and should be inputted with the format nactf{...}<br>
> Practice entering your flag here: nactf{fl4gz_4_d4yz}<br>
> -mcantillon

Flag in description: `nactf{fl4gz_4_d4yz}`


## Basics
Points: 30
> Tiffany no longer communicates in normal text. Weird, I know. She randomly sent me this message: **bmFjdGZ7YmE1MzVfYXIzX3N3MzN0fQ==**<br>
> Can you figure out what it means?<br>
> -mcantillon

Base64 decode: `nactf{ba535_ar3_sw33t}`


## Grep 0
Points: 50
> Sophia created this large, mysterious file. She might have said something about grap.. grapes? Find her flag!<br>
> -izhang05

Wait for file to download and then run `grep "nactf" flag.txt`: `nactf{gr3p_1s_r3ally_c00l_54a65e7}`


## Numbers
Points: 50
> What do the numbers mean?<br>
> -izhang05

Subtract 1 from each number and convert to ascii: `nactf{asc11_XB4RCR5}`


## Hashbrowns
Points: 50
> MD made 5 hashbrowns this morning and forgot to add salt and pepper. He took a bite out of one of them and found a piece of paper with this written on it: 5af554431d976fdc57ea02908a8e0ce6.<br>
> -izhang05

Put into [hashes.com](https://hashes.com/en/decrypt/hash): `nactf{secure_password}`


## Arithmetic
Points: 150
> Ian is exceptionally bad at arthimetic and needs some help on a problem: x + 2718281828 = 42. This should be simple... right?<br>
> `nc challenges.ctfd.io 30165`<br>
> -izhang05

We need to overflow the numbers, max val is 2<sup>32</sup> so we need to find 42 + 2<sup>32</sup>: `nactf{0verfl0w_1s_c00l_6e3bk1t5}`


## Survey

nactf{survey_flag12f93}
