from base64 import b64decode


def read_binary():
    ret = ""
    with open("binary.txt", 'r') as file:
        contents = file.read()

        for char in contents.split():
            ret += chr(int(char, 2))
    return ret.split('\n')[-1]


def main():
    step1 = read_binary()
    print(step1)
    step2 = b64decode(step1).decode()
    step2 = ''.join(step2.split('\n')[1:])
    print(step2)
    # Rot 10, then use quipqiup


if __name__ == "__main__":
    main()
