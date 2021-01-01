from utils.cryptography.analyze import block_ngrams, ngrams, prefix_block_ngrams

with open("output.txt") as f:
    data = f.read()
print(block_ngrams(data, 2))
print(prefix_block_ngrams(data, 2, 1))
print(ngrams(data, 1))

table = {
    '1': '2', # space
    '8': '0',
    '0': '6', # e
    'c': '5',
    'd': '7', # r
    'b': 'f', # t
    '3': '4',
    '2': 'e', # .
    '7': '9', # i
    '9': '1', # a
    '4': '3', # c
    'e': '8', # h
    '5': 'c', # l
    'a': 'd', # m
    'f': 'a', # j
    '6': 'b', # k
}
print(len(table))

print(data)
data = data.translate(str.maketrans(table))
s = ""
for i in range(0, len(data), 2):
    s += chr(int(data[i:i+2], 16))
print(s)