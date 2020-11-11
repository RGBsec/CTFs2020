from collections import Counter

with open("enc.txt") as f:
    text = f.read().strip()

print(len(text))
N = len(text) // 101
ans = ""
for i in range(0, N, 8):
    bits = [0] * 8
    for j in range(101):
        pos = N * j + i
        x = text[pos:pos+8]
        for idx, bit in enumerate(x):
            if bit == '0':
                bits[idx] -= 1
            else:
                bits[idx] += 1

    bits = ['1' if b > 0 else '0' for b in bits]
    num = int(''.join(bits), 2)
    ans += chr(num)
print(ans)