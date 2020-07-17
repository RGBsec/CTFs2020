# redpwnCTF 2020 Alien Transmissions v2 Writeup
by qpwoeirut

Category: Crypto<br>
Points: 481

> The aliens are at it again! We've discovered that their communications are in base 512 and have transcribed them in base 10. However, it seems like they used XOR encryption twice with two different keys! We do have some information:
>
> * This alien language consists of words delimitated by the character represented as 481
> * The two keys appear to be of length 21 and 19
> * The value of each character in these keys does not exceed 255
>
> Find these two keys for me; concatenate their ASCII encodings and wrap it in the flag format.

We're given a large file of the aliens' communications.
Since the key will be repeated every 21*19=399 times, we can use frequency analysis to break the encryption.
We can assume that the most common character will be 481, and from that we can get the combined 399-character key.
Then we need to separate the two keys.

If we know the first character of one of the keys, we can use that information to calculate the rest of the key.
Say we know the first character of the 19-character key.
Then we also know the first character of the 21-character key.
We also know the 19th character since the first key is repeated.
And since the 21-character key is repeated 19 times, we can recover the entire key.

But we don't know the first character.
Fortunately, we can just brute force it.
Then we can just print out each key and see which one makes sense.

Implementation at `solve_alien.py`.