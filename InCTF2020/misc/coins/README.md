# InCTF 2020 Coins Writeup
by qpwoeirut

Category: Misc<br>
Points: 100<br>

After connecting to nc and solving a proof of work we get this description:
> There exists a coin minting machine at Bi0S which is known for its extermely fast minting process. However out of every batch (N coins) it produces one coin is faulty (have a different weight compared to the other N-1 coins). You can get information of the xor of the weight of the coins from index i to index j (both included) by communicating with the minting machine. Find the faulty coin (coin with different weight) with minimum number of queries, as the minting machine has better things to do than answer your questions. Multiple batches are produced by the minting machine and it is gaurenteed that in each batch there is only one defective coin. Your query should be in the format "i j" (without the quotes) where both i and j should lie in the range [0, N). You can report the correct position (Of course after solving it) in the format "! index" (without the quotes) where index lies in the range [0, N). If you correctly identify the faulty coin for a batch, you will continue to the next batch. If a query is given in the wrong format or give a wrong answer you will be rejected.

## Explanation
This can be solved with a binary search on the location of the faulty coin.
We can take advantage of the fact that all the non-faulty coins have the same value.
If we know the value of the good coins, we can determine if the bad coin is in a certain range with one query.

The value of the good coins can be found by querying any two spots. 
If they match, we have the value of the good coins.
If they don't, that means that one of those two spots has the bad coin.
We can ask a third query and see which values don't match.

Once we have the value of the good coins we can run a binary search.
If the range we queried has an odd number of elements, then there are two possibilities.
If the bad coin is in the range, there will be an even number of good coins, whose xor sums will cancel out.
Then the value we get is the value of the bad coin.
If the bad coin isn't in the range, then we will get the value of the good coin.

If the range we queried has an even number of elements, then the final xor sum will either be 0 if there is no bad coin or the good coin xor the bad coin if the bad coin is present.
Since we can check if the bad coin is in a certain range, we can binary search on the bad coin's position in log2(n) queries.

The implementation is at `solve_coins.py`