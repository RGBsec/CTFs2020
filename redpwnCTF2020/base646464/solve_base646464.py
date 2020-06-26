"""
redpwnCTF 2020 Writeups
Challenge: base646464
Category: Crypto
Points: 145

As the challenge title hints, this is repeated base64 encoding.
The provided JavaScript file shows that the flag has been base 64 encoded 25 times.
To solve, we can just continuously decode and print the current text.
This program will eventually crash but at least we get the flag.
"""


from base64 import b64decode

with open('base646464.txt', 'r') as f:
    a = f.read()


while True:
    a = b64decode(a)
    print(a)