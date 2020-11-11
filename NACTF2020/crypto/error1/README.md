# NACTF 2020 Writeups: Error 1
Points: 350

> Pranay has decided that the previous error detection scheme is a little bit too inefficient... While eating his delicious HAM-filled Italian Sub at lunch, he came up with a new idea. Fortunately, he has also invested in a less noisy communication channel.<br>
> -izhang05

Hint:
> https://www.youtube.com/watch?v=X8jsijhllIA

## Explanation
I used the video provided in the hint to get all the information I needed.
The amazing simplicity of Hamming Codes makes the solution script easy to write.
I didn't read the provided source closely enough at first to notice that the index of each bit was shifted by 1, but everything after was pretty straightforward.
Implementation at `solve_error1.py`.

`nactf{hamm1ng_cod3s_546mv3q9a0te}`