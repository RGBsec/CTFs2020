def main():
    s = ""
    with open("zero.txt", 'rb') as file:
        for c in file.read():
            ch = chr(c)
            s += ch


if __name__ == "__main__":
    main()