# NACTF 2020 Writeups: Error 2
Points: 550
> Kayla decided she wants to use the previous error detection scheme for cryptography! After computing the normal error bits, she switched them around according to a secret key.<br>
> Note: enc.txt has been reuploaded. Please redownload the file if you downloaded before 12:00 am 10/31<br>
> -izhang05

## Explanation
We know that the key is of length 4, and that each position has about 15 options, which means we can simply brute force each key.
I reused a lot of the script from Error 1, and just added in the usage of the key.
From there we just try each key, and see what can be printed.

Flag: `nactf{err0r_c0rr3cti0n_w1th_th3_c0rr3ct_f1le_q73xer7k9}`