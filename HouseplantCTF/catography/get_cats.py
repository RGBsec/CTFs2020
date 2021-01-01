import matplotlib.pyplot as plt
from requests import get
from subprocess import Popen, PIPE, STDOUT

URL = "http://challs.houseplant.riceteacatpanda.wtf:30002"


def get_ids():
    ids = []
    cur = get(f"{URL}/api?page=0").json()
    i = 1
    while cur["has_more"] is True:
        cur = get(f"{URL}/api?page={i}").json()
        data = cur["data"]
        for photo in data:
            ids.append(photo["id"])

            if False or photo["link"].startswith("https://unsplash.com") is False or photo["authorLink"].startswith(
                    "https://unsplash.com") is False:
                print(photo)
        i += 1

    return ids


def write_ids():
    with open("catography/img_ids.txt", 'w') as file:
        for img_id in get_ids():
            file.write(img_id + '\n')


def get_pos(img_id):
    # with open(f"catography/images/{img_id}.jpg", 'wb') as file:
    #     file.write(get(f"{URL}/images/{img_id}.jpg").content)
    process = Popen(["exiftool", f"catography/images/{img_id}.jpg"], stdout=PIPE, stderr=STDOUT, universal_newlines=True)
    ret = ['', '']
    for tag in process.stdout:
        key, val = tag.split(':', maxsplit=1)
        if "GPS Latitude" in key and "Ref" not in key:
            ret[0] = val.strip().replace(" deg ", ' ')
        elif "GPS Longitude " in key and "Ref" not in key:
            ret[1] = val.strip().replace(" deg ", ' ')

    print(img_id, ': ', ret[0] + ', ' + ret[1])
    return ret[0] + ', ' + ret[1]


def write_pos():
    out = open("catography/coords.txt", 'w')
    with open("catography/img_ids.txt") as file:
        for img in file.read().split('\n'):
            out.write(get_pos(img) + '\n')

    out.close()


def to_decimal(s: str):
    tmp = s
    dec = 0
    d, s = s.split("°")
    dec += float(d)
    d, s = s.split("'")
    dec *= 100
    dec += float(d)
    d, s = s.split('"')
    dec *= 100
    dec += float(d)

    print(tmp, '->', dec)
    return dec


def plot():
    fig = plt.figure()
    ax1 = fig.add_subplot(111)

    X = []
    Y = []
    with open("dec_coords.txt", 'r') as coords:
        for coord in coords:
            print(coord)
            x, y = coord.split(', ')
            # dec_x = to_decimal(x)
            # dec_y = to_decimal(y)
            X.append(int(float(x)*10000))
            Y.append(int(float(y)*10000))

    ax1.set_title("Coords")
    ax1.scatter(X, Y, s=10, marker='o')
    plt.show()


def to_kml():
    kml = open("kml_coords.kml", 'w')
    kml.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    kml.write('<kml xmlns="http://earth.google.com/kml/2.0">\n')
    kml.write('<Document>\n')

    with open("dec_coords.txt", 'r') as coords:
        for tm, coord in enumerate(coords):
            kml.write(
f"""<Placemark>
    <TimeSpan>
        <begin>{1500+tm}-01</begin>
        <end>{1530+tm}-01</end>
    </TimeSpan>
    <Point><coordinates>{coord.strip()}</coordinates></Point>
</Placemark>
""")
    kml.write("</Document>\n</kml>")
    kml.close()



def main():
    # write_ids()
    # write_pos()
    to_kml()
    # get_ids()
    # plot()


if __name__ == "__main__":
    main()
