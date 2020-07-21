# Chujowy CTF 2020 Insanity1 Writeup
by qpwoeirut

> Tags: Misc<br>
> nc insanity1.chujowyc.tf 4004

This was a very weird challenge.
We're given nc, and connecting to that gets us:
> Welcome chCTF Sanity Check :D<br>
> What is 2+2: 

So we answer 4.<br>
Now we get:
> What number between 0 and 100 am I thinking about right now?

I guessed random numbers a couple times, and figured that since all the questions are the same the answers probably are too.
So I wrote a brute-force script to just guess all the numbers by continuously reopening connections.<br>
Turns out the answer was 81.

> xD xD The answer to the next one is in front of your eyes xD xD<br>
> What is 2+2: 

We get `2+2` again, but apparently the answer's not 4 this time.
But if we look at the output using our script, we see: `b'xD xD The answer to the next one is in front of your eyes xD xD\nThe answer is 42123 ;)\r                         \rWhat is 2+2:'`

And printing that final answer gets us the flag: `chCTF{Ez3_cha113ng3}`