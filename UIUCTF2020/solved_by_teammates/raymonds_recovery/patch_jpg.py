from os import listdir


def patch(filename):
    filename = "files/" + filename
    with open(filename, 'rb') as f:
        dat = f.read()

    if dat.startswith(b'\x00\x00\x00\rIHDR'):
        dat = b'\x89PNG\x0d\x0a\x1a\x0a' + dat
        print("patched as png", filename)
    elif dat.startswith(b'-1.3'):
        print("didn't patch", filename)
        return
    elif dat.startswith(b'\xe0\x00\x10JFIF') or dat.startswith(b'\xdb'):
        dat = b'\xff\xd8\xff' + dat
        print("patched as jpg", filename)
    elif dat.startswith(b'\x00\x00\x10JFIF'):
        dat = b'\xff\xd8\xff\xe0' + dat[1:]
        print("patched as jpg", filename)
    else:
        assert dat.startswith(b'\xff\xd8\xff'), dat[:20]

    with open(filename, 'wb') as f:
        f.write(dat)


files = listdir("files")
print(files)
for file in files:
    patch(file)