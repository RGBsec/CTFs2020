# CSICTF 2020 Mafia Writeup
by qpwoeirut

We can solve using randomized binary search with pruning optimizations.
We can keep an array of friends which stores the largest possible amount of money they might have.
Then we can start running binary search on a random friend's money.
As soon as we either know the exact amount of money they have, or that they have less money than our current maximum, we can stop.

Once we have found the maximum, we can stop and send our answer.
This approach should take 400-500 queries on average.
Friends are chosen at random in case the test data is constructed to be adversarial.

Implementation at `solve_mafia.py`.

`csictf{y0u_ar5_t8e_k!ng_0f_rAnd0mne55}`