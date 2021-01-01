# CyBRICS 2020 Lite Keyshooter Writeup
by qpwoeirut

Category: Forensic<br>
Difficulty: Baby<br>
Points: 50
> Author: Artur Khanov (@awengar)
> 
> His friend was filming while he was entering the password for the flag. OMG he's shooting letters from his fingers!
>
> Decrypt the flag.
>
> Files: keyshooter.tar.gz

We're given a video of someone encrypting `flag.txt` using OpenSSL.
We can see what the person is typing as the password.

## TL;DR
Just watch the video, bruteforce the password chars you can't see clearly.
Make sure you're decrypting with OpenSSL and not LibreSSL.

## Explanation
For a Baby challenge, this took our team a rather long time, thanks to the fact that some Macs use LibreSSL.
Most of the password is very obvious, although a few characters are obscured by the typer's right hand.
We can easily fix this by just brute forcing all possible passwords when we can't tell what character was pressed.

From here it was probably meant to be very straightforward - just try the passwords and see which one gets the flag.
But our team ran into an complication since the 2 of us that were working on the challenge both use Macs, and our OpenSSl implementation was some version of LibreSSL.
So we spent an extra hour wondering why none of our passwords worked, and even extracted frames out of the video to make sure we weren't missing something.
We also checked with the authors to make sure the password was in English and caps lock was off and all that.

Eventually we thought that maybe LibreSSL and the OpenSSL version used in the video would have different behaviors.
After crashing my computer by trying to simultaneously use a Windows VM and a Linux VM, I was able to run a Linux VM which had OpenSSL.
Our bruteforcing strategy worked and we got the flag.

Bruteforcing script at `solve_keyshooter.py`

Password: `mahchoudqotlzeeb`<br>
Flag: `cybrics{L00K_4ND_F0110w}`