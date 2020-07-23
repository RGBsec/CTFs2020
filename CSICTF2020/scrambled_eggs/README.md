# CSICTF 2020 Scrambled Eggs Writeup
by qpwoeirut

Category: Reversing<br>
Points: 499

> I like my eggs sunny side up, but I ended up scrambling them.

Files: scrambledeggs.py, scrambledeggs.txt

## Explanation
Just like in Esrever, `enc2` is very easy to reverse and `enc1` is a little harder.
In this challenge, all `enc1` does is rotate the input it's given.
So no matter how many times it's run we can easily get all of the possible inputs (just like in Esrever!).

The nested for loop is just some swapping of characters in the flag and keys.
The hardest part was probably the for loop at the end since we're not completely sure whether `a > 122` ever happens from the output we get.
But if we assume that all values will be lowercase letters we can get around that issue.
The `random.sample([key1, key2], 2)` can also be easily figured out by just trying both ordered pairs of keys.

Implementation at `solve_scrambled_eggs.py`.

Note: When trying to write the inverse of a function, remember to reverse `range` too!

`csictfaallbthebkingsbhorsesa`
`csictf{all_the_kings_horses}`