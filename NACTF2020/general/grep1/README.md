# NACTF 2020 Writeups: Grep 1
Points: 200

> Elaine hid a REGULAR flag among more than 1,000,000 fake ones! The flag was an EXPRESSION of her love for nactf, so the first 10 characters after "nactf{" only have the characters 'n', 'a', 'c', and the last 14 characters only have the characters 'c', 't' and 'f'. There are 52 characters in total, including nactf{}.<br>
> -izhang05


## Explanation
I have basically no regex knowledge so I just cheesed this with C++.
The implementation is pretty straightforward.

Flag: `nactf{caancanccnxfynhtjlgllctekilyagxctftcffcfcctft}`