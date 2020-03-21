import numpy as np
from random import gauss
from utils.morseCode import to_morse_code
morse = to_morse_code("test_message")
repeats = 1
pointed = []
for c in morse:
    if c == ".":
        pointed.extend([1 for x in range(10)])
    if c == "-":
        pointed.extend([1 for x in range(20)])
    if c == " ":
        pointed.extend([0 for x in range(20)])
    pointed.extend([0 for x in range(10)])

with open("test_morse2.txt", "w") as f:
    for _ in range(repeats):
        signal = pointed
        output = []
        for x, bit in enumerate(signal):
            output.append(bit + gauss(0,2))
        print(signal)
        print(output)

        signal = list(np.array(output) - .5)
        f.write('\n'.join([str(x) for x in signal])+"\n")
        print('\n'.join([str(x) for x in signal])+"\n")
f.close()
