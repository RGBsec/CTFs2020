from random import choice

from pwn import remote

r = remote("ege.q.2020.ugractf.ru", 17494)


def recv(check, substr=False):
    line = r.recvline(timeout=5)
    line = line.decode().strip()
    # print(line.strip())
    if substr:
        assert check in line, line
    else:
        assert line == check, line
    return line


def checkline(check, substr=False):
    try:
        recv(check, substr=substr)
        return True
    except AssertionError:
        return False


def welcome():
    global r
    if r.closed:
        r = remote("ege.q.2020.ugractf.ru", 17494)
    recv("Вас вітає електросистема оцінки знань в рамках підготовки до ЕГЭ!")
    recv("")
    token = "9c84fd6eff6c0fe45fa4fbf83f0e4315"
    # print("Sending token", token)
    r.sendline(token)
    recv("Введіть код учасника:")


opts = []


def interact():
    answers = dict()
    with open("use_ans", 'r') as f:
        for line in f:
            answers[line.split(',')[0]] = line.split(',')[1].strip()

    correct = 0
    lookups = 0
    while correct < 1337:
        try:
            recv("ЗАВДАННЯ", substr=True)
            question = recv("вони", substr=True)
            # print(question)
            if question in answers:
                print("[!!!] In table, looking up")
                lookups += 1
                opt = answers.get(question)
            else:
                opt = choice(opts)
            r.sendline(opt)
            if checkline("Так.", substr=True) is True:
                correct += 1
                print(f"[{correct}] Answer: {opt}")
                answers[question] = opt
            recv('')
        except AssertionError:
            with open("use_ans", 'w') as f:
                for k,v in answers.items():
                    f.write(f"{k},{v}\n")
            print(r.recvall(5).decode())
            print("Correct:", correct)
            print("Lookups:", lookups)
            raise


def main():
    while True:
        welcome()
        try:
            interact()
            break
        except AssertionError:
            print('-'.join('=' * 100))
            continue


if __name__ == '__main__':
    for i in range(50):
        opts.extend(["обидва", "обидві"])
    opts.append("обоє")
    main()