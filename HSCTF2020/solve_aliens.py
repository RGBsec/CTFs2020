def pprint(g: list):
    for r in g:
        print(r)
    print()


grid = []
with open("AlienMarking.txt", 'r') as inp:
    for line in inp:
        grid.append([int(n) for n in line.strip().split()])

# grid = [
#     [5, 7, 2, 6],
#     [4, 2, -1, 5],
#     [-1, 7, 6, 7],
#     [10, -1, -1, 8]
# ]

N = len(grid)
assert len(grid) == len(grid[0])

sums = [[grid[r][c] for c in range(N)] for r in range(N)]
negative = [[grid[r][c] == -1 for c in range(N)] for r in range(N)]
for r in range(N):
    for c in range(N):
        if r > 0:
            sums[r][c] += sums[r - 1][c]
            negative[r][c] ^= negative[r - 1][c]
        if c > 0:
            sums[r][c] += sums[r][c - 1]
            negative[r][c] ^= negative[r][c - 1]
        if r > 0 and c > 0:
            sums[r][c] -= sums[r - 1][c - 1]
            negative[r][c] ^= negative[r - 1][c - 1]

print("Prefix sum done")
ans = 0
for r1 in range(N):
    for c1 in range(N):
        print(f"Started {r1} {c1}")
        for r2 in range(r1, N):
            for c2 in range(c1, N):
                cur = sums[r2][c2]
                neg = negative[r2][c2]
                if r1 > 0 and c1 > 0:
                    cur -= sums[r1 - 1][c1 - 1]
                    neg ^= negative[r1 - 1][c1 - 1]
                elif r1 > 0:
                    cur -= sums[r1 - 1][c1]
                    neg ^= negative[r1 - 1][c1]
                elif c1 > 0:
                    cur -= sums[r1][c1 - 1]
                    neg ^= negative[r1][c1 - 1]

                if cur % 13 == 0:
                    if neg is True:
                        cur *= -1

                    ans += cur

# pprint(grid)
# pprint(sums)
# pprint(negative)
print(ans)
