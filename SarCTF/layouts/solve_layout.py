from os import chdir
import bz2
from zipfile import ZipFile, is_zipfile


def open_zip(file_path: str):
    file_path = file_path.split('/')[-1]
    print(f"Opening {file_path}")
    if is_zipfile(file_path) is False:
        return
    zip_file = ZipFile(file_path)
    print(zip_file.namelist())
    for name in zip_file.namelist():
        open_zip(zip_file.extract(name, pwd=file_path.split('.')[0].encode()))


if __name__ == "__main__":
    chdir("/Users/Stanley/CTFs/SarCTF2020/layouts/")
    file_name = "RWtm7A5f.zip"
    open_zip(file_name)