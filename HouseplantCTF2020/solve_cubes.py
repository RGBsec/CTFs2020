#!/usr/bin/env python3
"""
Find item frames and prints location
Based off of https://github.com/twoolie/NBT/blob/master/examples/chest_analysis.py
"""

import os, sys
from nbt.world import WorldFolder


class Position(object):
    def __init__(self, x, y, z, dtype=int):
        self.x = dtype(x)
        self.y = dtype(y)
        self.z = dtype(z)


class Entity(object):
    def __init__(self, type, pos):
        self.type = type
        self.pos = Position(*pos)


def item_frames_per_chunk(chunk):
    item_frames = []

    for entity in chunk['Entities']:
        if entity["id"].value == "minecraft:item_frame":
            x, y, z = entity["Pos"]
            item_frames.append(Entity("Item Frame", (x.value, y.value, z.value)))

    return item_frames


def print_results(chests):
    for chest in chests:
        print(f"{chest.type} at {chest.pos.x},{chest.pos.y},{chest.pos.z}")


def main(folder):
    world = WorldFolder(folder)

    try:
        for chunk in world.iter_nbt():
            print_results(item_frames_per_chunk(chunk["Level"]))
    except KeyboardInterrupt:
        return 75  # EX_TEMPFAIL

    return 0  # NOERR


if __name__ == '__main__':
    world_folder = os.path.normpath("cubes")
    if not os.path.exists(world_folder):
        print("Folder does not exist: " + world_folder)
        sys.exit(72)  # EX_IOERR

    sys.exit(main(world_folder))
