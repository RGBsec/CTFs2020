# X-Mas CTF 2020 Writeups: Santa Computing

Category: Misc<br>
Points: 476

> Our sources say that RCA is very close to a breakthrough. Discover where it all started.<br>
> Target: http://challs.xmas.htsp.ro:6003<br>
> Author: yakuhito

## Explanation
We need to reverse a JS file which is modifying a matrix.
It turns out this is actually pretty straightforward, since we can just apply the reverse operations in reverse order.
I originally didn't realize that `numOfCells` didn't change after flipping the cells in the square but besides that it was mostly simple.

The JS file was converted to python and then reversed.

`X-MAS{A_SMALL_WORLD_INSIDE_YOUR_BROWSER}`