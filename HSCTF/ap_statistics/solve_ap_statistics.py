import string
from collections import deque


def to_numbers(guess: str, rand: int) -> list:
    arr = [0 for _ in guess]
    arr[0] = ord('a') + rand
    for i in range(1, len(guess)):
        # print(arr)
        if (arr[i - 1] % 2) == 0:
            arr[i] = ord(guess[i]) + (arr[i - 1] - ord('a'))
        else:
            arr[i] = ord(guess[i]) - (arr[i - 1] - ord('a'))

        # print(arr[i])
        if arr[i] - ord('a') + 29 < 0 and ((arr[i] - ord('a')) % 29) != 0:  # emulate java mod of negative integers
            arr[i] = ((arr[i] - ord('a') + 29) % 29) + ord('a') - 29
        else:
            arr[i] = ((arr[i] - ord('a') + 29) % 29) + ord('a')
        # print(arr[i])
    assert -1 not in arr
    # print(arr)
    return swap_array(arr)


def swap_array(arr: list) -> list:
    for i in range(1, len(arr)):
        if arr[i - 1] <= arr[i]:
            flip(arr, i, i - 1)
    return arr


def to_string(arr: list) -> str:
    ans = ""
    for x in arr:
        ans = ans + chr(x)
    return ans


def flip(arr: list, a: int, b: int) -> None:
    tmp = arr[a]
    arr[a] = arr[b]
    arr[b] = tmp


def guess_flag(guess: str, strict_check=False) -> bool:
    target = "qtqnhuyj{fjw{rwhswzppfnfrz|qndfktceyba"
    # target = "uadiMVwY`}TjrhoJuJiXyL|{FE"

    if strict_check and len(guess) != len(target):
        return False

    distorted = to_string(swap_array(to_numbers(guess, 5)))
    # print(distorted + '\n')

    # if guess.startswith("flag"):
    #     print(guess, distorted)

    if strict_check:
        if distorted == target:
            return True
    else:
        if soft_check(distorted, target):
            return True
    return False


def soft_check(s: str, t: str) -> bool:
    return (t.startswith(s[:-2])
            and s[-2] in t[len(s) - 2:] and s[-1] in t[len(s) - 2:]
            )


def main():
    chars = string.ascii_lowercase + '{|}'
    possible = deque(["flag{"])
    flags = []
    while len(possible) > 0:
        # print(possible)
        current = possible.popleft()
        if guess_flag(current, strict_check=True) is True:
            print("FLAG:", current)
            flags.append(current)
            # break

        print(current)
        for c in chars:
            if guess_flag(current + c):
                possible.append(current + c)
    print(flags)
    flags = [flag for flag in flags if flag[-1] == '}' and flag.count('}') == 1 and flag.count('{') == 1]
    for flag in flags:
        print(flag)


if __name__ == '__main__':
    main()
    # guess_flag("flag{f")
