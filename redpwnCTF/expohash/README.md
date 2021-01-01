# redpwnCTF 2020 expohash Writeup
by qpwoeirut

Category: Misc<br>
Points: 491

> Fishy is trying to hack into a secret government website again!!!
>
> They learned from fishy's attempts last year, so they created a password of 10^5 integers, and each integer x in the password satisfies 0 <= x <= 2^31. However, this password was too long for them to check, so they made up a method that they hoped was quicker. They included 10^5 tests that the password checker will do.
>
> In each test, the computer checks from some left bound L to some right bound R, where 1 <= L <= R <= 10^5. The computer takes the xor of each value in the range L to R inclusive of the password and checks if that equals the expected value V. Fishy has found the the values for L, R, V for each test, but he needs your help to find a valid password. Can you help him?
>
> You will be given the L, R, and V values for each test, and each test will be on their own line. For example, the first few tests could look something like:
> ```
> 1 4 6
> 5 12 9
> 574 990 743485
> ...
> ```

This was the only algo problem of the CTF.
There's an array A with 10<sup>5</sup> numbers, and we are given xor sums of 10<sup>5</sup> intervals in A.
We need to find any values of A that work for the list of intervals.

(Solution is next paragraph)
I solved this with a few hours left in the CTF.
I tried a few approaches, including sorting by interval size and then trying to backtrack once I had multiple options.
That took a ridiculously long time, and didn't work.
I also tried searching for the solution online.
This problem seems standard enough that someone must have solved it.
But I couldn't find anything, although that might just be my bad searching skills.
I finally thought of the solution after contemplating the problem for a few days (and trying to implement some rather hopeless ideas).
Now to the solution...

We can simplify each interval so that no two intervals end in the same spot.
If any two intervals do end in the same spot, we can change the larger one to end right before the smaller one.
Formally, if we have L<sub>1</sub> < L<sub>2</sub> and R<sub>1</sub> = R<sub>2</sub>, then we can change R<sub>1</sub> = L<sub>2</sub> - 1 and V<sub>1</sub> to V<sub>1</sub> xor V<sub>2</sub>.
In this way, we can ensure every interval has a unique endpoint.

Then, we can go from left to right and fill in the values of the password.
Since at most one interval ends at any spot, we can use that spot to make sure the interval has the correct value.
The code to do so is below. It implements a segment tree (which is really overkill), but prefix sums should work fine too.
The segment tree is left over from a different failed approach from earlier.

Implementation at `clean-expohash.cpp`.

To solve the challenge from the nc server, I plugged in this code to a netcat wrapper I wrote in python.

Note: Technically this solution doesn't solve the problem since x could be equal to 2<sup>31</sup>.
That would cause some integer overflow.
But luckily x is always less than 2<sup>31</sup> for the tests we need to solve.