import pygame

class Tile(object):
  LENGTH = 32
  SPIKE_LENGTH = 12
  NUM_TILES = 17

  EMPTY = 0
  WALL = 1
  SPIKE_U = 2
  SPIKE_D = 3
  SPIKE_L = 4
  SPIKE_R = 5
  ORB_SPIKE_U = 6
  RND_SPIKE_U = 7
  RND_SPIKE_D = 8
  ORB_HOLDER_OFF = 9
  ORB_HOLDER_ON = 10
  ORB = 11
  FLAG = 12
  PLAYER_SPAWN = 13
  TUX_SPAWN = 14
  IE_SPAWN = 15
  T_REX_SPAWN = 16

  def __init__(self, id, image):
    self.id = id
    self.image = image

  def isSolid(self):
    return (self.id == Tile.WALL or self.isOrbHolder() or self.isSpike())

  def isOrbHolder(self):
    return self.id == Tile.ORB_HOLDER_OFF or self.id == Tile.ORB_HOLDER_ON

  def isSpike(self):
    return (self.id == Tile.SPIKE_U or self.id == Tile.SPIKE_D
            or self.id == Tile.SPIKE_L or self.id == Tile.SPIKE_R
            or self.id == Tile.ORB_SPIKE_U or self.id == Tile.RND_SPIKE_U
            or self.id == Tile.RND_SPIKE_D)

  def isEnemySpawn(self):
    return (self.id == Tile.TUX_SPAWN or self.id == Tile.IE_SPAWN
            or self.id == Tile.T_REX_SPAWN)

  def render(self, display, x, y, cameraX, cameraY):
    if self.image:
      display.blit(
          self.image, (x * Tile.LENGTH - cameraX, y * Tile.LENGTH - cameraY))

  def getCollRect(self):
    if (self.id == Tile.SPIKE_U or self.id == Tile.ORB_SPIKE_U
        or self.id == Tile.RND_SPIKE_U):
      return pygame.Rect(0, Tile.LENGTH - Tile.SPIKE_LENGTH,
                         Tile.LENGTH, Tile.SPIKE_LENGTH)
    elif self.id == Tile.SPIKE_D or self.id == Tile.RND_SPIKE_D:
      return pygame.Rect(0, 0, Tile.LENGTH, Tile.SPIKE_LENGTH)
    elif self.id == Tile.SPIKE_L:
      return pygame.Rect(Tile.LENGTH - Tile.SPIKE_LENGTH, 0,
                         Tile.SPIKE_LENGTH, Tile.LENGTH)
    elif self.id == Tile.SPIKE_R:
      return pygame.Rect(0, 0, Tile.SPIKE_LENGTH, Tile.LENGTH)
    elif self.isOrbHolder():
      return pygame.Rect(10, 22, 12, 10)
    elif self.id == Tile.ORB:
      return pygame.Rect(10, 21, 11, 11)
    elif self.id == Tile.FLAG:
      return pygame.Rect(13, 18, 11, 14)
    return pygame.Rect(0, 0, Tile.LENGTH, Tile.LENGTH)

  def getDamageRect(self):
    if (self.id == Tile.SPIKE_U or self.id == Tile.ORB_SPIKE_U
        or self.id == Tile.RND_SPIKE_U):
      return pygame.Rect(1, Tile.LENGTH - Tile.SPIKE_LENGTH - 1,
                         Tile.LENGTH - 2, 0)
    elif self.id == Tile.SPIKE_D or self.id == Tile.RND_SPIKE_D:
      return pygame.Rect(1, Tile.SPIKE_LENGTH + 1, Tile.LENGTH - 2, 0)
    elif self.id == Tile.SPIKE_L:
      return pygame.Rect(Tile.LENGTH - Tile.SPIKE_LENGTH - 1, 1,
                         0, Tile.LENGTH - 2)
    elif self.id == Tile.SPIKE_R:
      return pygame.Rect(Tile.SPIKE_LENGTH + 1, 1, 0, Tile.LENGTH - 2)
    return pygame.Rect(0, 0, Tile.LENGTH, Tile.LENGTH)
