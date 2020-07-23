# CSICTF 2020 Quick Math Writeup
by qpwoeirut

Category: Crypto<br>
Points: 486

> Ben has encrypted a message with the same value of 'e' for 3 public moduli -
> n1 = 86812553978993
> n2 = 81744303091421 
> n3 = 83695120256591 
> and got the cipher texts - 
> c1 = 8875674977048
> c2 = 70744354709710
> c3 = 29146719498409.
> Find the original message. (Wrap it with csictf{})

## Explanation
The moduli are all very small, and attempting to factor them reveals that they are prime.
This means that decryption is very easy (once we have e) since the totient of a prime p is just p-1.
We can assume that e will be reasonably small and just try all values of e.
We can check if e is right since the correct e will result in all 3 decrypts having the same value.

Doing this reveals that e is just 3.
We also get our plaintext: `683435743464`.

But this doesn't convert to anything readable.
At this point I got stuck for some time, and even sent a DM to the admins asking if everything was correct.
Then pretty much right afterward, I realized that the number looked a lot like readable hex, and got the flag.

`csictf{h45t4d}`

I didnt't really like the second part of the challenge.
The way that messages are converted to and from numbers in RSA is very standard, and using a custom conversion just adds a lot of guessiness.
There's no reason to do that, and from an admin perspective you probably get a lot of DMs about it as well.