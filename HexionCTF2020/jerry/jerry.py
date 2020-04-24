"""
Writeup for Hexion CTF 2020
By Stanley

Challenge: T&J
Category: Misc
Points: 846 (as of time of writing)
Description:
    Can you help Tom catch Jerry?
    Author: Idan

We are given jerry.pcapng, which is a pcap of USB mouse movement. (This took my team and I way longer to figure out than it should have, given that Jerry from Tom and Jerry is a mouse.)
My team found a script at https://github.com/WangYihang/UsbMiceDataHacker which I used. The script had to be ported from python2 to python3, and my version of tshark functions differently that the original script expected.
I also changed some other small things to make the script more like my style.
Once that was out of the way, I ran the code but got a bunch of scribbles. (PUT IMAGE OF SCRIBBLES FROM DISCORD HERE, https://media.discordapp.net/attachments/698372772321296485/698705799379157012/jerry_plot.png)
My teammates noticed that it did look a little like a flag, and by shrinking the marker size and widening the image we got this: (PUT WIDE IMAGE HERE, https://media.discordapp.net/attachments/698372772321296485/698710191553773578/jerry_flag.png?width=2036&height=463)
The writing was still messed up, since the script logged every movement, not just when the mouse was pressed. After that was changed, we got the flag.
(IMAGE WITH FLAG, https://media.discordapp.net/attachments/698372772321296485/698710870536224768/jerry_flag.png?width=2036&height=322)
"""
import os
import matplotlib.pyplot as plt


pcapFilePath = "jerry.pcapng"
DataFileName = "usb.dat"
data = []


def main():
    X = []
    Y = []
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
            # depending on what tshark you have, the output may be separated by ":" instead
    # print(data)

    # handle each movement
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

        # don't record the movement if the mouse is not pressed down
        if capture_data[0] == "00":
            continue

        X.append(mouseX)
        Y.append(-mouseY)

    fig = plt.figure()
    ax1 = fig.add_subplot(111)

    # print(X)
    # print(Y)

    ax1.set_title("File " + pcapFilePath)
    ax1.scatter(X[:-10], Y[:-10], s=1, c='r', marker='o')

    # show the plot
    plt.show()

    # clean temp data
    os.system("rm ./%s" % (DataFileName))


if __name__ == "__main__":
    main()
