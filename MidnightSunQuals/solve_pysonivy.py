import base64
from hashlib import sha256
from marshal import loads

chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"

PAYLOAD = base64.b64decode('rTZrDbYKPWjLavV/23Z0UdDW9D2xPo3xq/wgYkJqUsoERezJoxCGTtY0uNJcfFD6hrcQl5s8dwvujQvfAnRpPScvhXA6JEtbirUs3YTOeutX4scEOfhAlbfSsAuK1bdU9CGeO2HuYVcKncqlKKuiMWfI+KbE3aPiBks0TnXxVEr/mBGoUEcYgCMo1sne3wo1Gy+CBP5R1dHBXd7+0sDKIPNEGZOnQYTzhhorCc/DNNs3Qkf2XhFmlaQ2lWPgvSZA68b1jvrIR0Z05hdMbJGgICfJGy136J82m8O/GneW5XRDzxcUUBklR1jPjZyPjhxvKw/ML1822h67APWXsUCP67Iy2ku025rwWJe2bX/mzAChUq+euK1Ji8UagQiZ3PAC1CsR0V71jc6CPMI6IRSNHnCqiRJZHuL9CH+j+rNJbBc2X1TPdntBf3tlgQg9MMJJ4TgLazfA8eq0ZTQ9UK/o52kfY2uh7HK1N+xIZWeIAKXY6Msidg/NUFjhRThIR6DqV3G33IFTmLahxIirBta91UjOZcIpu3UpL2Fa60pLwX6rlQIA13nKxx/dOkvfJUfvsUOK5TcwzzxpcVgfemC/KxNZ4hajFnttIDXS0yo2DZxvt5uTxY258mY6xTHMohkEJ77y8HhBlMw/bXJKWt+315mdiakjQn/gLyH13Mf2XGmTD92brPpF8H2oaGsQzj7l6jkyo24dMslPHJ/vpr9heKTAYyvgqPaGlJCTyPHe41diumg1nSB81t5kMw4lJ1gOD3XJOWeuN76bNP0vh/7g5IEZ7ugGHl3zq/7Rua5rKvDIvHxudiolnLxlz3Zv7/pqztZY9t0vpsYj/fYuLtLrRJFcYZY/BxG7DR0Y5EI4MfpUb+M53/g/ziCjpYFNchq2qVTfw3uP3AUyBv4Eoh+91tOSJMLhl1lPgBP/vnBhP2kBq6Ca1JHeZZVyEyWEXHcoSm2K7NV2EFekWuT5k81oX6QljarnX5uZuZiq0WOhyaFKGeLHNc9SPWSWkRmO2esQO1Rt9bglE7ogg70rBT588GQttG58A3c+zhthFMuoN04S1SK+99tg2mzYX4DxgMHGsyt3ScZlMisOpEkrnmrV0G8WKZzt/DSs6/sau89YJKCySDGp6aObpnC+11d234pcx1MhA9GMQ9yXReYSylTmwcJkYdFoPL2YfHnw2fzP45SnhWmQORqR+ZfPBheHwTTRdUkCwOnMlJEbrEPu9OId')

def rc4(data, key):
    res = []
    S = []
    for i in range(256):
        S.append(i)

    j = 0
    for i in range(256):
        j = (j + S[i] + key[(i % len(key))]) % 256
        S[j], S[i] = S[i], S[j]

    i = 0
    j = 0
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[j], S[i] = S[i], S[j]
        K = S[((S[i] + S[j]) % 256)]
        res.append(K ^ b)

    return bytes(res)


def test(login) -> bool:
    x = sha256(bytes((66 ^ i ^ x for i, x in enumerate(login)))).hexdigest().encode('ascii')
    # print(x)
    payload_dec = rc4(PAYLOAD, x)
    # print(payload_dec)
    try:
        payload_code = loads(payload_dec)
        # print(payload_code)
    except Exception:
        return False

    # try:
    #     types.FunctionType(payload_code, globals(), 'payload')
    return str(type(payload_code)) == "<class 'code'>"
    # except TypeError:
    #     return False


if __name__ == '__main__':
    # login_file = open("pysonivy_logins.txt", 'w')
    # Tried up to plAn**
    for c1 in chars:
        for c2 in chars:
            print(c1,c2)
            for c3 in chars:
                for c4 in chars:
                    login = f'pl{c1}{c2}{c3}{c4}'
                    if test(login.encode('ascii')):
                        print(login)
                        # login_file.write(login + '\n')
    # login_file.close()
