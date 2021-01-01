#!/usr/bin/env python3

import os
import socketserver
import string
import threading
from time import *
import time
import binascii

ROUNDS = 4
BLOCK_SIZE = 8

sbox = [77, 100, 87, 71, 69, 66, 3, 210, 13, 104, 78, 79, 65, 106, 91, 203, 86, 84, 215, 82, 25, 80, 81, 88, 95, 94, 111, 222, 73, 24, 67, 74, 103, 108, 102, 70, 35, 97, 99, 98, 45, 92, 125, 110, 41, 168, 107, 105, 116, 117, 115, 118, 113, 112, 85, 114, 93, 124, 253, 127, 89, 216, 75, 126, 101, 16, 38, 6, 5, 96, 1, 19, 11, 76, 15, 2, 10, 64, 59, 72, 21, 20, 22, 18, 17, 177, 27, 83, 23, 28, 63, 14, 9, 154, 31, 90, 37, 4, 39, 32, 33, 224, 43, 34, 109, 44, 47, 46, 40, 36, 42, 130, 53, 52, 151, 54, 49, 48, 55, 50, 121, 60, 191, 62, 123, 56, 58, 120, 205, 229, 199, 228, 193, 68, 195, 194, 141, 204, 239, 236, 192, 233, 207, 238, 221, 196, 197, 198, 209, 144, 211, 208, 217, 220, 223, 158, 201, 218, 139, 26, 165, 164, 243, 230, 225, 226, 231, 242, 173, 252, 255, 206, 235, 232, 227, 202, 245, 212, 246, 214, 241, 240, 145, 182, 237, 188, 119, 254, 249, 248, 122, 250, 129, 148, 167, 132, 163, 0, 7, 131, 133, 12, 159, 134, 137, 200, 219, 138, 149, 140, 135, 150, 136, 152, 147, 146, 157, 29, 143, 156, 153, 8, 155, 187, 180, 162, 175, 166, 181, 128, 51, 170, 169, 172, 174, 142, 161, 160, 171, 234, 213, 244, 179, 190, 185, 176, 183, 178, 189, 184, 247, 30, 57, 61, 251, 186]
perm = [1, 57, 6, 31, 30, 7, 26, 45, 21, 19, 63, 48, 41, 2, 0, 3, 4, 15, 43, 16, 62, 49, 55, 53, 50, 25, 47, 32, 14, 38, 60, 13, 10, 23, 35, 36, 22, 52, 51, 28, 18, 39, 58, 42, 8, 20, 33, 27, 37, 11, 12, 56, 34, 29, 46, 24, 59, 54, 44, 5, 40, 9, 61, 17]
key = open("flag.txt", "rb").read().strip()

class Service(socketserver.BaseRequestHandler):

    def key_expansion(self, key):
        keys = [None] * 4
        keys[0] = key[0:4] + key[12:16]
        keys[1] = key[4:8] + key[8:12]
        keys[2] = key[4:8] + key[8:12]
        keys[3] = key[0:4] + key[12:16]
        return keys

    def apply_sbox(self, pt):
        ct = b''
        for byte in pt:
            ct += bytes([sbox[byte]])
        return ct

    def apply_perm(self, pt):
        pt = bin(int.from_bytes(pt, 'big'))[2:].zfill(64)
        ct = [None] * 64
        for i, c in enumerate(pt):
            ct[perm[i]] = c
        return bytes([int(''.join(ct[i : i + 8]), 2) for i in range(0, len(ct), 8)])

    def apply_key(self, pt, key):
        ct = b''
        for a, b in zip(pt, key):
            ct += bytes([a ^ b])
        return ct

    def handle(self):
        keys = self.key_expansion(key)
        for i in range(65536):
            pt = os.urandom(8)
            ct = pt
            for i in range(ROUNDS):
                ct = self.apply_sbox(ct)
                ct = self.apply_perm(ct)
                ct = self.apply_key(ct, keys[i])
            self.send(str((int.from_bytes(pt, 'big'), int.from_bytes(ct, 'big'))))

    def send(self, string, newline=True):
        if type(string) is str:
            string = string.encode("utf-8")

        if newline:
            string = string + b"\n"
        self.request.sendall(string)

    def receive(self, prompt="> "):
        self.send(prompt, newline=False)
        return self.request.recv(4096).strip()


class ThreadedService(
    socketserver.ThreadingMixIn,
    socketserver.TCPServer,
    socketserver.DatagramRequestHandler,
):
    pass


def main():

    port = 8097
    host = "0.0.0.0"

    service = Service
    server = ThreadedService((host, port), service)
    server.allow_reuse_address = True

    server_thread = threading.Thread(target=server.serve_forever)

    server_thread.daemon = True
    server_thread.start()

    print("Server started on " + str(server.server_address) + "!")

    # Now let the main thread just wait...
    while True:
        sleep(10)


if __name__ == "__main__":
    main()