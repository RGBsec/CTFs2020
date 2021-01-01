import zipfile, os

for i in range(1000, 0, -1):
    with open(f"flag/direction.txt") as f:
        direction = f.read().strip()
    os.remove(f"flag/direction.txt")
    with zipfile.ZipFile(f"flag/{i}{direction}.zip") as myfile:
        myfile.extractall('./flag')
    os.remove(f"flag/{i}left.zip")
    os.remove(f"flag/{i}right.zip")

with open("flag/flag.txt") as f:
    print(f.read().strip())