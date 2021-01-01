# CSAW CTF Quals 2020 Writeups: Perfect Secrecy
by qpwoeirut

Category: Crypto<br>
Points: 50<br>
Description: Alice sent over a couple of images with sensitive information to Bob, encrypted with a pre-shared key. It is the most secure encryption scheme, theoretically...<br>
Files: image1.png, image2.png

![image1](image1.png)
![image2](image2.png)

## Explanation
We get two images of random-looking noise.
From here I just tried XOR on the images and it worked.
At this point the challenge had a lot of solves so it had to be something simple.
I wrote a quick script to XOR the pixels at `solve_perfect_secrecy.py`.

![flag](out.png)