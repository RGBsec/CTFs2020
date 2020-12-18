# X-Mas CTF 2020 Writeups: Help a Santa helper?

Category: Crypto<br>
Points: 240

> Hey, I found some secret server on which Krampus stores his private details.<br>
> It seems like he has some kind of difficult crypto challenge instead of a login, if we pass that we should get access to valuable information.<br>
> Let's give it a try, what do you say?<br>
> Target: nc challs.xmas.htsp.ro 1004<br>
> Author: Gabies

## Explanation
Taking a look at the `update` function for the `Hash`, we can immediately notice that it uses xor on a string that we directly control.
With this knowledge, we can encrypt a message of 16 null bytes.
This gets rid of the xor operation, since xoring with 0 returns the same number.
The result of this hash will be same as the AES encryption of 16 null bytes.
Then for our next block we can use this hash for the `get_elem` call.
Since each block is xor-ed with the hash from the previous block, we'll be AES encrypting null bytes again.
That will produce the same hash, which gets xor-ed with itself again, returning a string of 16 null bytes.

Now all we need is another way to get a hash of just null bytes.
The easiest way to do this is just with an empty message since that passes `is_hex` and doesn't change the Hash state at all.

`X-MAS{C0l1i5ion_4t7ack5_4r3_c0o1!_4ls0_ch3ck_0u7_NSUCRYPTO_fda233}`
