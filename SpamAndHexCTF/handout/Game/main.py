#!/Users/Stanley/CTFs/venv/bin/python3
from sys import argv
from Game import Game
from Flag import printFlags

if len(argv) <= 1 or argv[1] not in ["game", "replay", "check"]:
  print("./main.py <mode>")
  print("possible modes: game, replay, check")
  exit(0)

mode = argv[1]
game = Game(mode)

while True:
  if not game.tick():
    break

if game.won():
  print("WON!")
  if mode == "check":
    printFlags(game.getCompletionTime())
elif game.died():
  print("Died :C")
elif game.reachedEndOfReplay():
  print("Reached end of replay input :C")
else:
  print("Closed window")

del game
