"""
Writeup for Hexion CTF 2020
By Stanley
Challenge: X0R
Points: 188 (as of time of writing)
Description: XOR is best method for OTPs, especially for flags.

We are given an encrypted flag and an encryption program.
The encryption program generates a key of letters of length 8 to 15, inclusive
Then the flag is repeatedly xored by cycling the key for each index

What follows is a brute-force method to retrieve the flag
The script will probably print multiple flags (assuming you let it run - it takes a long time)
These flags all follow the flag format but only the one that is an actual word is correct
"""

from string import ascii_letters, digits
from itertools import cycle


# read the encrypted flag
with open("flag.enc", "r") as file:
    enc = file.read()


# utility function to check whether the given string matches the flag format
# checks if any of the characters are not letters, digits, underscores, or curly brackets
valid_chars = set(ascii_letters + digits + '_{}')


def valid(dec: str) -> bool:
    return len(set(dec) - valid_chars) == 0


# recurse through all possible keys between length 8 and 15, inclusive
def rec(cur: list):
    if len(cur) >= 16:  # key has to be less than 16 chars
        return
    if len(cur) >= 8:  # if key has correct length, try it on the flag
        key_gen = cycle(cur)
        data = []
        for i in range(len(enc)):
            k = next(key_gen)
            data.append(chr(ord(enc[i]) ^ ord(k)))

        dec = ''.join(data)
        if not valid(dec[:len(cur)]):  # if the part of the key we've determined doesn't work, then stop
            return
        if valid(dec):  # if the flag is in a valid format, print the decrypted flag and key
            print(dec, ''.join(cur))

    # if len(cur) <= 12:  # this prints every now and then to show which keys have been checked
    #     print(cur)

    for c in ascii_letters:
        rec(cur + [c])


# we can figure out the first 7 characters of the key manually, since we know the flag starts with "hexCTF{"
# the key is represented as a list so that string concatenation doesn't take forever
key = list("JtmZzCJ")
rec(key)

# hexCTF{supercalifragilisticexpialidocious}
# I didn't actually run the script to the end to get the real flag
# It printed hexCTF{ySpercalikTagilistcEexpialinIcious} first and I figured that it was probably the word supercalifragilisticexpialidocious, which it was
