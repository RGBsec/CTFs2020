from requests import get
from utils.flag_strings import leet_flag_chars
from itertools import product

chars_lower = set("FAKE-X-MAS{d1s_i\$_a_SaMpL3_Fl4g_n0t_Th3_c0Rr3c7_one_karen_l1k3s_HuMu5.0123456789}")
charset = chars_lower.union({x.upper() for x in chars_lower})
chars = [c for c in leet_flag_chars if c in charset]
print(chars)

for L in range(1, 10):
    for s in product(chars, repeat=L):
        print(''.join(s), get(f"http://challs.xmas.htsp.ro:3001/?flag={''.join(s)}").text)