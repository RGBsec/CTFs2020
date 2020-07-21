# Chujowy CTF 2020 grownup RSA Writeup
by qpwoeirut

> Tags: crypto
> This RSA kid has grown up a bit.
>
> Oh, the actual secret is only 31 bytes long but it was padded from the left with 97 spaces.
>
> Author: @enedil
>
> Downloads: grownuprsa.txt

Since we already know 75% of the secret, we can apply Coppersmith's attack to recover the rest.
To be honest, I'm not completely sure how Coppersmith's attack and `small_roots` really works, but I was able to blackbox it.
The final sage code is almost completely copied from [RSA-and-LLL-attacks](https://github.com/mimoo/RSA-and-LLL-attacks).
Most of `main` is from the readme, and the `coppersmith_howgrave_univariate` function is verbatim from [coppersmith.sage](https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/coppersmith.sage), minus the debug prints.

Running the script gets us `chCTF{D1d_y0u_us3_sm4l1_r00ts?}`

Also, blackboxing CTF challenges is really not recommended.
I spent a lot of time fixing dumb mistakes related to a lack of experience in sage and a lack of understanding of how basics of attack works.
I still don't really understand how the attack works though - I'm only a rising sophomore in high school and don't have the math background required.