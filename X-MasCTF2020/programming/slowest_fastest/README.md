# X-Mas CTF 2020 Writeups: Slowest Fastest

Category: Programming<br>
Points: 457

> This is an emergency, we need you to help us organize our gift building process. We're in a hurry so let's go!<br>
> Target: nc challs.xmas.htsp.ro 6055<br>
> Authors: Gabies, Nutu

## Explanation
We can binary search on the answer, since if you can finish in x days, you can finish in x+1 days.
To check whether it is possible to finish in x days, we can greedily assign the slower worker as many times as possible while still being able to finish.
If the number of fast workers required is more than the number we have, it's not possible.
Otherwise it works.

I spent a majority of the time on this problem dealing with slow internet issues.
At one point I tried connecting my computer with ethernet and then using ice packs to speed things up as much as possible (as you can probably guess, I have a Mac).
But that still timed out around test 80-90 out of 100.
In the end my teammate just ran it and got the flag.

`X-MAS{l0l_h0w_15_7h1s_4_b1n4ry_s34rch_pr0bl3m?}`