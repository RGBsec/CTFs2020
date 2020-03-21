from collections import Counter


def add_data():
    with open("dora_file", 'a+') as file:
        b64 = input("b64: ")
        while b64 != 'q':
            ans = input("ans: ")
            file.write(f"{b64} {ans}")
            b64 = input("\nb64: ")


def analyze():
    arr = []
    with open("dora_file", 'r') as file:
        for line in file:
            arr.append(line.split()[0])
    ctr = Counter(arr)
    print(ctr.most_common())


if __name__ == "__main__":
    # add_data()
    analyze()