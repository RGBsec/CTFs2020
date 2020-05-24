s = ["w3lc0me","1337","players", "and", "good", "luck", "with", "the", "game"]

morse = ".- -. -.."

from utils.morseCode import from_morse_code
print(from_morse_code(morse))

print('OOO{' + '_'.join(s) + '}')