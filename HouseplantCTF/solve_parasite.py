from utils.morseCode import from_morse_code

with open("Parasite.txt") as file:
    s = file.read()

s = s.replace('   ', ' _ ')
print(s)
s = from_morse_code(s, escaped="_")
print(s)

# https://en.wikipedia.org/wiki/SKATS
# 희망은진정한기생종입니다
# rtcp{hope_is_a_true_parasite}