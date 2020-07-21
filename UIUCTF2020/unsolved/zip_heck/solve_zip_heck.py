import os
import zipfile


def run(filepath: str):
    os.chdir(filepath)
    print("Dir:", os.getcwd())
    for i in range(int(1e9)):
        if i & 63 == 0:
            print(i)
            os.system("du -a -k tmp")
            with open("tmp/flag.zip", 'rb') as f, open(f"tmp/flag{i}.zip", 'wb') as out:
                out.write(f.read())
        with zipfile.ZipFile("tmp/flag.zip") as file:
            dat = file.read("flag.zip")
        with open("tmp/flag.zip", 'wb') as out:
            out.write(dat)

run(".")
