#!/usr/bin/env python3

import struct
import time


def out(line):
    for i in line:
        print(i, end="", flush=True)
        # time.sleep(0.005)


class Command:
    info = ""

    @staticmethod
    def policy(value, round):
        raise NotImplementedError


class L(Command):
    info = "Налево"

    @staticmethod
    def policy(value, round):
        return (value + 13 + round)*37


class R(Command):
    info = "Направо"

    @staticmethod
    def policy(value, round):
        return abs((value + 37 - round)*17)


class STOP(Command):
    info = "Остановиться"

    @staticmethod
    def policy(value, round):
        return value + round*13


class DASH(Command):
    info = "Метнуться"

    @staticmethod
    def policy(value, round):
        return (value<<2) + round


class UP(Command):
    info = "Наверх"

    @staticmethod
    def policy(value, round):
        return value + 1337


class TALK(Command):
    info = "Поговорить"

    @staticmethod
    def policy(value, round):
        return value*9 + (value%round)


class B(Command):
    info = "RUSH B"

    @staticmethod
    def policy(value, round):
        return value*ord("B")


class A(Command):
    info = "RUSH A"

    @staticmethod
    def policy(value, round):
        return value*ord("A")


class S(Command):
    info = "По коням!"

    @staticmethod
    def policy(value, round):
        return value + ord("S") + ord("T") + ord("A") + ord("R") + ord("T")


class SIDE(Command):
    info = "В сторону!"

    @staticmethod
    def policy(value, round):
        return value + 4 * round


class DOWN(Command):
    info = "Вниз"

    @staticmethod
    def policy(value, round):
        return value + 9 * round

def logo():
    out(""" __     __ _       _                  _                 
 \ \   / /| |     | |                (_)                
  \ \_/ /_| | __ _| | ___ _ __  _ __  _ _   _           
   \   / _` |/ _` | |/ _ \ '_ \| '_ \| | | | |          
    | | (_| | (_| | |  __/ | | | | | | | |_| |          
 __ |_|\__,_|\__,_|_|\___|_| |_|_| |_|_|\__, |  _       
 \ \   / /                   | |         __/ | | |      
  \ \_/ / __  _ __ __ ___   _| | ___ _ _|___/__| |_ ___ 
   \   / '_ \| '__/ _` \ \ / / |/ _ \ '_ \ / _ \ __/ __|
    | || |_) | | | (_| |\ V /| |  __/ | | |  __/ || (__ 
    |_|| .__/|_|  \__,_| \_/ |_|\___|_| |_|\___|\__\___|
       | |                                             
       |_|               (c) CatGirl Industrial 2020   """)
    out("\n")
    out("Подключение . . . . . . . . . . Успех!")
    out("\n")
    out("Приветствуем тебя в консоли удаленого управления. Следи за лимитом на команды. Вслушивайся в музыку и приведи своего человека к победе!")
    out("\n")

def play():
    init_state = b"\x90\x9c\t\xc5\x9aP`5Ez\xf6\x98\xb7\xe5#\x9fR\x13\x9eJ\xd3\xf6'{\x19f;p\xb0\x85E\xeb\x9e\xbd\xc8\xfai\xf3\x9a@"
    print(struct.unpack("<40B", init_state))
    remote = 1
    turns = (8+4)*6 + (3+7) + (4+4)
    subclasses = list(Command.__subclasses__())
    for i in range(turns):
        print(f"Ход ({i}/{turns})")
        print("Возможный выбор:")
        for j in range(len(subclasses)):
            print(f"{j} {subclasses[j].info}")
        a = int(input("> "))
        if a not in range(len(subclasses)):
            exit(1)
        remote = subclasses[a].policy(remote, i)
    out("Отлично поиграли! Давай проведу проверки, затем выдам флаг\n")
    r = [int(i) for i in list(str(remote))]
    assert sum(r) == 482
    assert len(r) == 97
    assert r[2] == r[3] == r[12] == r[13] == r[24] == r[32] == r[42] == r[47] == r[53] == r[57] == r[61] == r[67] == r[86]
    assert r[16] == r[44] == r[48] == r[54] == r[77] == r[79] == r[93]
    assert r[39] == r[51] == r[62] == r[64] == r[69]  == r[84] == r[89]
    assert r[0] == r[7] == r[11] == r[19] == r[29] == r[41] == r[46] == r[58] == r[66] == r[80]
    assert r[26] == r[31] == r[33] == r[38] == r[81] == r[96]
    assert r[5] == r[17] == r[55] == r[56] == r[74]
    assert r[6] == r[9] == r[21] == r[50] == r[60] == r[63] == r[65] == r[70] == r[72] == r[83] == r[90] == r[91] == r[92]
    assert r[14] == r[18] == r[34] == r[43] == r[59] == r[68] == r[87] == r[88]
    b = 1
    for i in r:
        b *= i if i != 0 else 1
    assert b == 2760417597537019351700664712711713267399333595054080000000

    ans = struct.unpack("<40B", init_state)

    out("Прикольно! Расшифровываю флаг\n")
    unp = remote.to_bytes(300, byteorder='little')[:40]
    out("".join([chr(unp[i] ^ init_state[i]) for i in range(40)]))
    out("\n")


if __name__ == "__main__":
    # logo()
    play()