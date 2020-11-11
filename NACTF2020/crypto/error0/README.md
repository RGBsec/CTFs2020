# NACTF 2020 Writeups: Error 0

Points: 150
> Rahul has been trying to send a message to me through a really noisy communication channel. Repeating the message 101 times should do the trick!<br>
> -izhang05

## Explanation
The description tells us that the message is repeated 101 times (although for whatever reason it took me a bit to realize that).
From here we can just analyze the amount of times each bit is set in each repeated message.
Then we take the most frequent choice, and decode into ascii.

`nactf{n01sy_n013j_|\|()|$'/}`