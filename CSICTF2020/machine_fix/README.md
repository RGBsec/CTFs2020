# CSICTF 2020 Machine Fix Writeup
by qpwoeirut

Category: Misc<br>
Points: 467

> We ran a code on a machine a few years ago. It is still running however we forgot what it was meant for. It completed n=523693181734689806809285195318 iterations of the loop and broke down. We want the answer but cannot wait a few more years. Find the answer after n iterations to get the flag.<br>
> The flag would be of the format csictf{answer_you_get_from_above}.

Files: code.py

## Explanation
The answer is the number of differences between pairs of consecutive numbers' trinary representation.
We can do some observations to easily solve this problem.

Since the pairs of numbers differ by 1, the last digit will always be different.
Then the second-to-last digit will only be different if our numbers are like 10<sub>3</sub> and 02<sub>3</sub>.
This will happen every 3 pairs. We can continue this pattern until we've calculated all the differences in each digit.

Our final answer is `N/1 + N/3 + N/9 + N/27 + ...`

Implementation at `solve_machine_fix.py`.

`csictf{785539772602034710213927792950}`