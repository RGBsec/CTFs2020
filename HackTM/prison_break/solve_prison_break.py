MOD = 999999937

if __name__ == "__main__":
    A = [0] * pow(10, 7)
    with open("prison_break.txt") as file:
        for line in file:
            a, b, c = line.split()
            a = int(a) - 1
            b = int(b) - 1
            c = int(c) % 10
            A[a] += c
            A[b] -= c

    ans = max(1, A[0] % 10)
    for i in range(1, len(A)):
        A[i] += A[i-1]
        A[i] %= 10
        if A[i] != 0:
            ans *= A[i]
            ans %= MOD

    print(ans)