with open("Think_OUT_THE_BOX.txt", 'r') as f:
    print(''.join([chr(len(part)) for part in f.read().strip().split(',')]))
