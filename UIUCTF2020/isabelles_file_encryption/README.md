# UIUCTF 2020 Isabelle's File Encrypt Writeup
by qpwoeirut

Category: Crypto<br>
Points: 100<br>
Description:<br>
> Isabelle wanted to password-protect her files, but there wasn't any room in the budget for BitLocker! So she made her own program. But now she lost her password and can't decrypt one of her super important files! Can you help her out?
>
> Author: potatoboy69

Files: blackmail_encrypted, super_secret_encryption.py

## Explanation
We have an encrypted file and its encryptor.
Looking at the encryptor gets us some important information:
* The string "Isabelle" is in the plaintext
* The password has 8 characters
* The password only has alphabetic characters

The encryption itself is an XOR cipher with some "spice" added in.
The spice is just rotating the MSB to be LSB.

## Failed Solution
Originally I assumed that the file would be readable English, so I tried some frequency analysis.
The key was only 8 bytes long, and we had a lot of text.
But that didn't turn up anything.

## Solution
The solution was to use the string "Isabelle" as the crib in the plaintext.
We can go through the entire file and assume that's the spot where "Isabelle" is.
Then we can reconstruct what the password would be if our assumption was correct.
The easy way to do this is just by brute forcing each byte, since the encryption only uses one byte of the key at a time.
If the password we get has only alphabetic characters, we can add it to a list of potential passwords.

From here we can use the provided decryption function and check if its output contains the flag format.
If it does we can print out the flag and its surrounding bytes.

Note that the passwords we calculate need to be rotated, since it repeats every 8 bytes.
But since we're checking every byte, the password won't line up with the boundaries.

Implementation at `solve_isabelle.py`.