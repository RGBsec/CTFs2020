# X-Mas CTF 2020 Writeups: Santa Computing

Category: Hardware<br>
Points: 388

> Santa is still using that old hunk as his main computer huh? He keeps bragging about how his laughably outdated hardware and software is immune to all these fancy new modern vulnerabilities. While that might be true, someone please tell him that speed might be a security issue as well...<br>
> Target: nc challs.xmas.htsp.ro 5051
> Author: Milkdrop

## Explanation
The server is an oracle which tells us if the password we enter is a prefix of the real password.
If it is, it won't output anything. If it's not it'll say incorrect password.
We can execute a simple attack that appends to our password one char at a time.

`X-MAS{S1D3CH4NN3LZ?wtf!!}`