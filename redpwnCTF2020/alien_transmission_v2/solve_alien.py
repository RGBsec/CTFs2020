"""
redpwnCTF 2020 Writeups
Challenge: Alien Transmissions v2
Category: Crypto
Points: 481


"""


from collections import Counter
from utils.basics import ords_to_ascii

LEN1 = 21
LEN2 = 19
keys = []


def calc_combined_key():
    with open("alien.txt", 'r') as f:
        nums = [int(line) for line in f]

    for i in range(LEN1 * LEN2):
        common = Counter([nums[n] for n in range(i, len(nums), LEN1 * LEN2)]).most_common(1)
        keys.append(481 ^ common[0][0])
    print(keys)


done1 = [False] * LEN1
done2 = [False] * LEN2
key1 = [0] * LEN1
key2 = [0] * LEN2


def calc_keys(idx):
    if done1[idx % LEN1] and not done2[idx % LEN2]:
        key2[idx % LEN2] = key1[idx % LEN1] ^ keys[idx]
        done2[idx % LEN2] = True
        for i in range(idx % LEN2, len(keys), LEN2):
            calc_keys(i)
    if not done1[idx % LEN1] and done2[idx % LEN2]:
        key1[idx % LEN1] = key2[idx % LEN2] ^ keys[idx]
        done1[idx % LEN1] = True
        for i in range(idx % LEN1, len(keys), LEN1):
            calc_keys(i)


def fill(lst, val):
    for i in range(len(lst)):
        lst[i] = val


def main():
    calc_combined_key()

    for start in range(32, 256):
        fill(done1, False)
        fill(done2, False)

        done1[0] = True
        key1[0] = start
        calc_keys(0)

        assert all(done1) and all(done2)
        print(ords_to_ascii(key1))
        print(ords_to_ascii(key2))


if __name__ == '__main__':
    main()

# h3r3'5_th3_f1r5t_h4lf_th3_53c0nd_15_th15