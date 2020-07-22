# CSICTF 2020 Machine Fix Writeup
by qpwoeirut

The answer is the number of differences between pairs of consecutive numbers' trinary representation.
We can do some observations to easily solve this problem.

Since the pairs of numbers differ by 1, the last digit will always be different.
Then the second-to-last digit will only be different if our numbers are like 10<sub>3</sub> and 02<sub>3</sub>.
This will happen every 3 pairs. We can continue this pattern until we've calculated all the differences in each digit.

Our final answer is `N/1 + N/3 + N/9 + N/27 + ...`

Implementation at `solve_machine_fix.py`.