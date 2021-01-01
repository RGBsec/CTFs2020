def main():
    N = 523693181734689806809285195318

    div = 1

    ans = 0
    while div <= N:
        ans += N // div
        div *= 3

    print("csictf{" + str(ans) + "}")
    # print(ans, brute(N))


def brute(N):
    def convert(n):
        if n == 0:
            return '0'
        nums = []
        while n:
            n, r = divmod(n, 3)
            nums.append(str(r))
        return ''.join(reversed(nums))

    count = 0
    n = 1
    while n <= N:
        str1 = convert(n)
        str2 = convert(n - 1)
        str2 = '0' * (len(str1) - len(str2)) + str2
        print(str1, str2)
        for i in range(len(str1)):
            if str1[i] != str2[i]:
                count += 1
        n += 1

    return count

if __name__ == "__main__":
    main()