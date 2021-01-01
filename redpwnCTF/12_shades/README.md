# redpwnCTF 2020 12 Shades of Redpwn Writeup
by qpwoeirut

Category: Crypto<br>
Points: 429

> Everyone's favorite guess god Tux just sent me a flag that he somehow encrypted with a color wheel!
>
> I don't even know where to start, the wheel looks more like a clock than a cipher... can you help me crack the code?

I think this was the most annoying crypto challenge of redpwnCTF.
We get 2 images of colors. One is a color wheel and the other is the ciphertext.
I didn't want to transcribe the images by hand, so I wrote a PIL script to go through the ciphertext image and get each color.
Then I started guessing different encryptions.
Every two colors were paired in the ciphertext, and the first color was usually in the same general area of the color wheel.
I originally multiplied the first color by 10, and spent a long time rotating and offsetting the color wheel positions.
In the end, the cipher is just the location of the first color, times 12, plus the location of the second color.
Locations start at 0, at the top of the circle.
Implementation at `solve_12_shades.py`.