with open('rev-warmup', 'rb') as f:
    last = '\n'
    for c in f.read():
        ch = chr(c ^ 42)
        if ch != '*':
            print(ch, end='')
            last = ch
        elif last != '\n':
            print()
            last = '\n'
