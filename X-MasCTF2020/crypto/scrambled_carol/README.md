# X-Mas CTF 2020 Writeups: Scrambled Carol

Category: Crypto<br>
Points: 47

> I downloaded this carol a few days ago, and then I started reverse engineering some malware... Somehow my carol got scrambled after that, and next to it appeared some sort of weird script.<br>
> Can you help me recover the carol? It was a very good one.<br>
> Note: Challenge does not follow the normal flag format. Upload as lowercase.<br>
> Author: Gabies

## Explanation
The plaintext is enciphered by converting it to hex, and then encrypting the hex digits.
This leaves open a vulnerability to frequency analysis, since most letters start with aa 5, 6, or 7 (depending on upper/lowercase).
In addition, we're also given the mapped values for 2 and 0 immediately, since we know that the space should be the most common character.
From there, we can use frequency analysis based on blocks of 2, and see which ones appear most often.
Those should correspond to the most frequent letters in English.

`xmaswasneverasgoodasitisthisyear`