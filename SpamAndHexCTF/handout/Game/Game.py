import os
# pygame pls, don't spam my stdout :(
os.environ['PYGAME_HIDE_SUPPORT_PROMPT'] = "hide"
import pygame
import sys
from Tux import Tux
from IE import IE
from TRex import TRex
from Map import Map
from Renderer import Renderer
from Player import Player
from Tile import Tile
from Input import Input
from Rnd import Rnd

class Game(object):
  FPS = 30

  def __init__(self, mode):

    self.mode = mode
    replay = []
    if self.mode == "replay" or self.mode == "check":
      replay = self.loadReplay()
      if self.mode == "replay":
        print("replaying...", flush=True)
      else:
        print("checking...", flush=True)

    pygame.init()

    self.fpsClock = pygame.time.Clock()
    self.renderer = Renderer(self.mode)
    self.tickGroup = pygame.sprite.Group()
    self.playerGroup = pygame.sprite.Group()
    self.enemyGroup = pygame.sprite.Group()

    self.input = Input(self.mode, replay)
    self.rnd = Rnd(self.input)
    self.map = Map(self.renderer, self.rnd, self.mode)
    self.spawnEntities()

  def __del__(self):
    pygame.quit()
    if (self.mode == "game"):
      self.writeReplayFile("../replay.txt")
      print("Wrote replay input to replay.txt", flush=True)

  def loadReplay(self):
    result = []
    try:
      print("Input replay file + empty line", flush=True)
      for line in sys.stdin:
        line = line.strip()
        if len(line) == 0:
          break
        result.append(int(line[:5], 2))
        if len(result) > 10000:
           raise "Input too long"
      if len(result) == 0:
        raise "Input empty"
    except:
      print("Bad input :C", flush=True)
      exit(1)
    return result


  def spawnEntities(self):
    x, y = self.map.getPlayerStartPos()
    player = Player(self.renderer, self.input, self.map, self.enemyGroup, x, y)
    self.tickGroup.add(player)
    self.playerGroup.add(player)

    for data in self.map.getEnemyStartPos():
      x, y, type = data
      if type == Tile.TUX_SPAWN:
        enemy = Tux(self.renderer, self.map, self.playerGroup, x, y)
      elif type == Tile.IE_SPAWN:
        enemy = IE(self.renderer, self.map, self.playerGroup, x, y)
      elif type == Tile.T_REX_SPAWN:
        enemy = TRex(self.renderer, self.map, self.rnd, self.playerGroup, x, y)
      else:
        exit(1)
      self.tickGroup.add(enemy)
      self.enemyGroup.add(enemy)

  def tick(self):
    if self.mode == "check":
      events = []
    else:
      events = pygame.event.get()
      for event in events:
        if event.type == pygame.locals.QUIT:
          return False

    self.input.tick(events)
    for sprite in self.tickGroup.sprites():
      sprite.tick()
    self.map.tick()
    self.renderer.render()

    if self.mode != "check":
      self.fpsClock.tick(Game.FPS)

    if self.won() or self.died() or self.reachedEndOfReplay():
      return False
    return True

  def won(self):
    for player in self.playerGroup.sprites():
      if player.holdingFlagTimer == 90:
        return True

  def died(self):
    return len(self.playerGroup.sprites()) == 0

  def reachedEndOfReplay(self):
    return self.input.reachedEndOfReplay()

  def writeReplayFile(self, path):
    self.input.writeReplayFile(path)

  def getCompletionTime(self):
    return self.input.pos
