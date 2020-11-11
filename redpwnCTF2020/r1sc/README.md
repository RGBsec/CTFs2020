# r1sc

I solved this 7/22/2020. A bit late to submit for the CTF, but better late than never?

Method: probably unintended. I just brute forced it with angr after realizing the format of the binary (the fact that it asks for a password). Generic angr solve, with a few well-known tricks: lines 9-12 restrict the search space to printable characters to speed it up, `load_options={"auto_load_libs": False}` does the same in line 4, and line 21 is an extra constraint given that we know the flag format.

