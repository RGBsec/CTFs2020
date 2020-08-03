from utils.basics import ords_to_ascii

with open("hm.png", 'rb') as f1, open("hmmmm.png", 'rb') as f2:
    img1 = f1.read()
    img2 = f2.read()
print(len(img1), len(img2))

diffs = []
for b1, b2 in zip(img1, img2):
    if b1 != b2:
        diffs.append((b1, b2))

print(diffs)
print(len(diffs))
print(ords_to_ascii([diff[1] for diff in diffs]))