# CSICTF 2020 Friends Writeup
by qpwoeirut

Category: Misc<br>
Points: 480
> I made a really complicated math function. Check it out.
> `nc chall.csivit.com 30425`

Files: namo.py

## Explanation
We're provided a script which does some fancy math stuff and then checks for equality with our input.
I have no idea what the math actually is doing, but I decided on a whim to try sending NaN, and it worked.

After doing that we get some stuff which I think is Hindi - Google Translate says it is but refuses to actually translate.
But we can look at its format and see that most of it's repeated - the only changes are the number and the character in quotes.
So we can parse this to reassemble the flag.

I have no idea why the challenge authors couldn't just give us the flag.
All the second part does is make people take a longer time.
It's very easy to figure out (probably even easier if you speak Hindi), and someone could easily manually put together the flag after a few minutes.
I ended up spending around 5 times longer parsing the output than I did solving the actual challenge.

Implementation of server interaction and parsing at `solve_namo.py`.

`csictf{my_n4n_15_4_gr34t_c00k}`