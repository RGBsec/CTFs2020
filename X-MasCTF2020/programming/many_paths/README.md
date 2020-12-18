# X-Mas CTF 2020 Writeups: Many Paths

Category: Programming<br>
Points: 167

> Today in Santa's course in Advanced Graph Algorithms, Santa told us about the adjacency matrix of an undirected graph. I'm sure this last problem, he gave us is unsolvable, but I don't know much, maybe you do.<br>
> Target: nc challs.xmas.htsp.ro 6053<br>
> Authors: Gabies, Nutu

## Explanation
This can be solved with dynamic programming in O(N<sup>2</sup>L) time, which is plenty fast for the problem.
Our DP state is `dp[len][x]`, which stores the number of paths from node 1 to node `x` that are of length `len`.
So our final answer will be `dp[L][N]`.

Our transition to calculate `dp[len][u]` will be to sum up all of `dp[len - 1][v]` for all `v` where there is an edge between `u` and `v`.
This "expands" our path by adding the edge between `u` and `v`.

Since we have O(NL) states and each transition is O(N), the total runtime will be O(N<sup>2</sup>L).

The flag implies that this was meant to be solved with matrix exponentiation, but this runs quickly enough in C++.
To communicate with the server, I reused and modified an old program that piped input and output between the server and C++ program.

`X-MAS{n0b0dy_3xp3c73d_th3_m47r1x_3xp0n3n71a7i0n}`