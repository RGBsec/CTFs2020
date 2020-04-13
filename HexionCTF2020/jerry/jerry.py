#!/usr/bin/env python
# coding:utf-8

import os
import matplotlib.pyplot as plt


class ActionTypes:
    LEFT = "green"
    RIGHT = "blue"
    MOVE = "red"
    UNKNOWN = "brown"


pcapFilePath = "jerry.pcapng"
DataFileName = "usb.dat"
data = []


def main():
    X = []
    Y = []
    atype = []
    mouseX = 0
    mouseY = 0

    # get data of pcap
    command = "tshark -r %s -T fields -e usb.capdata > %s" % (pcapFilePath, DataFileName)
    print(command)
    os.system(command)

    # read data
    with open(DataFileName, "r") as f:
        for line in f:
            data.append(line[:8].strip())
    print(data)

    # handle move
    for dat in data:
        capture_data = [dat[i:i + 2] for i in range(len(dat))]
        if len(capture_data) == 8:
            horizontal = 2  # -
            vertical = 4  # |
        elif len(capture_data) == 4:
            horizontal = 1  # -
            vertical = 2  # |
        else:
            continue

        offsetX = int(capture_data[horizontal], 16)
        offsetY = int(capture_data[vertical], 16)
        if offsetX > 127:
            offsetX -= 256
        if offsetY > 127:
            offsetY -= 256
        mouseX += offsetX
        mouseY += offsetY
        if capture_data[0] == "01":
            # print("[+] left click")
            atype.append(ActionTypes.LEFT)
        elif capture_data[0] == "02":
            # print "[+] right click"
            atype.append(ActionTypes.RIGHT)
        elif capture_data[0] == "00":
            continue
        #     # print "[+] mouse move"
        #     atype.append(ActionTypes.MOVE)

        X.append(mouseX)
        Y.append(-mouseY)

    fig = plt.figure()
    ax1 = fig.add_subplot(111)

    print(X)
    print(Y)

    ax1.set_title("File " + pcapFilePath)
    ax1.scatter(X, Y, s=1, c=atype, marker='o')
    plt.show()

    # clean temp data
    os.system("rm ./%s" % (DataFileName))


if __name__ == "__main__":
    main()
