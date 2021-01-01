from requests import get

prev = ""
ct = 0
URL = "http://challs.xmas.htsp.ro:1344"
for _ in range(10000):
    resp = get(URL).text
    try:
        lines = set([line.strip() for line in resp.split('\n') if line.strip()])
        if "X-MAS" in resp or 'MTMzNw' not in resp or len(lines) != 62 or (len(prev) > 0 and prev != resp):
            print(resp)
            break
    except Exception:
        print(resp)

    prev = resp

    ct += 1
    if ct % 10 == 0:
        print(ct)