from base64 import b64decode

with open('base646464.txt', 'r') as f:
    a = f.read()


while True:
    a = b64decode(a)
    print(a)