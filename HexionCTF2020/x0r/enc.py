from random import choice, randint
from string import ascii_letters
from itertools import cycle

key = ''.join([choice(ascii_letters) for i in range(randint(8, 16))])

with open("flag.txt", "r") as file:
    flag = file.read()

key_gen = cycle(key)
data = []
for i in range(len(flag)):
    data.append(chr(ord(flag[i]) ^ ord(next(key_gen))))

with open("flag.enc", "w+") as file:
    file.write(''.join(data))