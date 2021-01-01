from base64 import b64decode
import pyshark

cap = pyshark.FileCapture("challenge.pcap", include_raw=True, use_json=True)

src = set()
dst = set()
for c in cap:
    src.add(c.ip.src)
    dst.add(c.ip.dst)
    if c.length > 58:
        print(c.number)
        data = c.get_raw_packet().split(b"\x00")[-1]
        if b"data" in data:
            data = data.split(b":")[-1].strip(b' ').strip(b"}").strip(b'"')
            print(len(data), len(data) % 4)
            if len(data) % 4 > 0:
                data = data[:-(len(data) % 4)]

            data = b64decode(data)

        filename = f"packets/packet{c.number}"
        if data.startswith(b"\xff\xd8\xff"):
            filename += ".jpg"
        elif data.isascii():
            filename += ".txt"
            print(data)
        with open(filename, 'wb') as out:
            out.write(data)
    else:
        assert b"data" not in c.get_raw_packet()

print(src)
print(dst)