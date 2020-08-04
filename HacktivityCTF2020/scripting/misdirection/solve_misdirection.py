from bs4 import BeautifulSoup
from requests import get

url = "http://jh2i.com:50011/site/"
req = get(url, allow_redirects=False)

soup = BeautifulSoup(req.text, features='lxml')
links = soup.find_all("a")
links = [link['href'] for link in links if link['href'].endswith('php')]
print(links)

chars = []
for link in links:
    req = get(url + link, allow_redirects=False)
    text = req.text.split()
    if len(text) == 7:
        chars.append((int(text[1]), text[-1]))

chars.sort()
print(''.join([t[1] for t in chars]))