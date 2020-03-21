from utils.netcat import Netcat
from utils.rsa_util import get_pq


def get_keys() -> None:
    nc = Netcat("138.68.67.161", 60005)
    while '>' not in nc.get_response():
        pass

    with open('bad_keys.txt', 'w') as file:
        for i in range(10000):
            if i % 100 == 0:
                print(f"finished getting {i} keys")
            nc.send('k\n'.encode())
            end = False
            while not end:
                resp = nc.get_response()
                for line in resp.split('\n'):
                    if '>' in line:
                        end = True
                        break
                    if line.startswith("((6"):
                        nums = line.replace('(', '').replace(')', '').replace(' ', '').split(',')
                        file.write(f"{int(nums[0])} {int(nums[1])} {int(nums[2])}\n")

        nc.close()


def compare_keys() -> None:
    pub_file = open('RSA_PUB', 'r')
    pub_e, pub_n = eval(pub_file.readline())
    pub_e = int(pub_e)
    pub_n = int(pub_n)
    pub_file.close()

    factors = []
    with open("bad_keys.txt", 'r') as file:
        for line in file:
            e, n, d = line.split()
            e = int(e)
            n = int(n)
            d = int(d)
            if d < 0:
                continue
            if e != pub_e:
                print(e,pub_e)
                print("e doesn't match!")
                continue

            try:
                tup = get_pq(n, d, e)
                factors.append(tup[0])
                factors.append(tup[1])
            except ValueError:
                print(f"error with n={n}, d={d}, e={e}")

    # print(factors)
    for factor in factors:
        if pub_n % factor == 0:
            print(factor, pub_n//factor)


if __name__ == "__main__":
    # get_keys()
    compare_keys()