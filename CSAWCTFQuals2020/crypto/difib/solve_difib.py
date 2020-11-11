import string
from utils.cryptography.bifid import Bifid, key_from_phrase
from gunnCryptoClub.cryptanalysis.chiSquaredTest import calculate_chi_squared

chars = set(string.ascii_lowercase)

with open("message") as f:
    enc = f.read().strip()

results = []
with open("ramblings") as f:
    for line in f:
        line = line.strip().lower()
        for c in string.punctuation + ' ’':
            line = line.replace(c, '')
        assert set(line) == chars
        cipher = Bifid(key_from_phrase(line))
        for i in range(1, len(enc) + 1):
            dec = cipher.decrypt(enc, i)
            results.append((calculate_chi_squared(dec), dec))
        cipher = Bifid(key_from_phrase(line[::-1]))
        for i in range(1, len(enc) + 1):
            dec = cipher.decrypt(enc, i)
            results.append((calculate_chi_squared(dec), dec))

results.sort(reverse=False)
print(results[:10])