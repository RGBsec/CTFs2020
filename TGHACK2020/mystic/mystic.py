with open("mystic.png", 'rb') as file:
    dat = file.read()

print(dat)
print(type(dat))
dat = bytes([d^42 for d in dat])

with open("mystic.dat", 'wb') as file:
    file.write(dat)