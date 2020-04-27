from itertools import cycle

from utils.morseCode import from_morse_code

s = "-- -.-- ..-. .-. .. . -. -.. .-- .... --- .-- .- ... -... .-.. .. -. -.. --..-- .-- .- ... ... .. - - .. -. --. .- - .-. ..- ... ... .. .- -. .. -. - . .-. -. .- - .. --- -. .- .-.. .- .. .-. .--. --- .-. - .-- .. - .... .- - .- .--. .--. .... --- -. . .-.-.-"

print(from_morse_code(s))

with open("Special_Message.txt") as f:
    s = f.read()

# s = s.replace(" Ноль ", '0')
# s = s.replace(' _ ', '_')
# print(s)
