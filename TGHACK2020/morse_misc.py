from utils.basics import to_ascii
from utils.morseCode import from_morse_code

s1 = "4c 53 41 74 4c 53 34 67 4c 69 34 74 4c 53 30 67 4c 53 30 74 4c 53 30 67 65 79 34 74 4c 53 41 75 49 43 38 67"
s2 = "14 96 c4 76 03 35 c4 76 03 35 c4 47 14 96 c4 57 43 34 94 67 14 96 c4 57 03 34 94 57 14 96 c4 57 03 34 94 57 14 96 c4 76 43 35 c4"[::-1]
s3 = "76 49 43 34 67 4c 69 34 75 49 43 30 74 4c 53 41 76 49 43 34 75 49 43 30 75 49 43 38 67 4c 53 30 74 49 43 34 75 4c 53 41 75 4c 53"
s4 = "d3 d3 14 94 93 24 96 c4 76 43 35 c4 57 43 34 94 57 43 34 94 57 43 35 c4 57 14 97 c4 76 43"[::-1]

s = ' '.join([s1,s2,s3,s4])
print(s)
print(to_ascii(s))

morse = "- --. ..--- ----- {.-- . / -. . . -.. . -.. / ... --- -- . / . ... --- / .. -. / --- ..- .-. / .-.. .. ..-. . }"
morse = morse.replace('/', '_').replace('{', "{ ")
print(from_morse_code(morse, escaped="{}_").replace('_', ' '))