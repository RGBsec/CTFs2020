from requests import get

nums = set()
URL = "http://challs.xmas.htsp.ro:1341"
for _ in range(10000):
    resp = get(URL).text
    print(resp)
    if "X-MAS" in resp:
        break