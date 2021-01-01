import pygame

from math import floor, ceil

from Tile import Tile

class RndSpike(object):
  def __init__(self, x, y, map, rnd):
    self.x = x
    self.y = y
    self.map = map
    self.rnd = rnd
    self.on = True
    self.changeTimer = 0
    self.sfx = pygame.sprite.Group()

  def tick(self):
    if self.changeTimer > 0:
      self.changeTimer -= 1
      return

    change = self.rnd.randint(0, 99) < 5
    if change:
      self.changeTimer = 10
      if self.on:
        self.on = False
        self.map.setTile(self.x, self.y - 1, Tile.EMPTY)
        self.map.setTile(self.x, self.y, Tile.EMPTY)
      else:
        self.on = True
        self.map.setTile(self.x, self.y, Tile.RND_SPIKE_U)
        self.map.setTile(self.x, self.y - 1, Tile.RND_SPIKE_D)
      state = "on" if self.on else "off"
      self.sfx.add(self.map.renderer.addSfx(
          self.x * Tile.LENGTH, (self.y - 1) * Tile.LENGTH,
          "rnd-spike-d-%s" % state))
      self.sfx.add(self.map.renderer.addSfx(
          self.x * Tile.LENGTH, self.y * Tile.LENGTH,
          "rnd-spike-u-%s" % state))

class Map(pygame.sprite.Sprite):
  def __init__(self, renderer, rnd, mode):
    super(Map, self).__init__()
    self.renderer = renderer
    self.rnd = rnd
    self.mode = mode
    self.tiles = self.loadTiles()
    self.map = self.loadMap()
    self.rndSpikes = self.loadRndSpikes()
    renderer.sprites.add(self)

  def loadTiles(self):
    tiles = {}
    if self.mode == "check":
      for i in range(Tile.NUM_TILES):
        tiles[i] = Tile(i, None)
    else:
      tileset_image = pygame.image.load("Graphics/tileset.png").convert_alpha()
      if (tileset_image.get_width() % Tile.LENGTH != 0
          or tileset_image.get_height() % Tile.LENGTH != 0):
        exit(1)

      tile_id = 0
      for y in range(int(tileset_image.get_height() / Tile.LENGTH)):
        for x in range(int(tileset_image.get_width() / Tile.LENGTH)):
          rect = (x*Tile.LENGTH, y*Tile.LENGTH, Tile.LENGTH, Tile.LENGTH)
          tile_image = tileset_image.subsurface(rect)
          tiles[tile_id] = Tile(tile_id, tile_image)
          tile_id += 1

    return tiles

  def loadMap(self):
    map = []
    with open("Map/map.txt") as f:
      map_text =  f.read()

    for line in map_text.strip().split("\n"):
      map_line = []
      for chunk in line.strip().split(","):
        map_line.append(int(chunk))
      map.append(map_line)
    return map

  def loadRndSpikes(self):
    spikes = []
    for y in range(len(self.map)):
      for x in range(len(self.map[0])):
        id = self.tiles[self.map[y][x]].id
        if id == Tile.RND_SPIKE_U:
          spikes.append(RndSpike(x, y, self, self.rnd))
    return spikes

  def getPlayerStartPos(self):
    for y in range(len(self.map)):
      for x in range(len(self.map[0])):
        if self.tiles[self.map[y][x]].id == Tile.PLAYER_SPAWN:
          return (x * Tile.LENGTH + Tile.LENGTH / 2, (y + 1) * Tile.LENGTH)
    return None

  def getEnemyStartPos(self):
    result = []
    for y in range(len(self.map)):
      for x in range(len(self.map[0])):
        tile = self.tiles[self.map[y][x]]
        if tile.isEnemySpawn():
          result.append((x * Tile.LENGTH + Tile.LENGTH / 2,
                         (y + 1) * Tile.LENGTH, tile.id))
    return result

  def getRndSpike(self, x, y):
    for spike in self.rndSpikes:
      if spike.x == x and spike.y == y:
        return spike
    return None

  def render(self, display, cameraX, cameraY):
    for y in range(len(self.map)):
      for x in range(len(self.map[0])):
        tile = self.tiles[self.map[y][x]]

        # Don't draw rnd spike tiles if there's an SFX over it.
        if (tile.id == Tile.RND_SPIKE_U
            and len(self.getRndSpike(x, y).sfx.sprites()) > 0):
            continue
        if (tile.id == Tile.RND_SPIKE_D
            and len(self.getRndSpike(x, y + 1).sfx.sprites()) > 0):
            continue

        tile.render(display, x, y, cameraX, cameraY)

  def getTile(self, x, y):
    if x < 0 or y < 0 or x >= len(self.map[0]) or y >= len(self.map):
      return None
    return self.tiles[self.map[y][x]]

  def setTile(self, x, y, id):
    if x < 0 or y < 0 or x >= len(self.map[0]) or y >= len(self.map):
      return
    self.map[y][x] = id

  def getCloseTileCollRects(self, rect, id):
    result = []
    for x in range(floor(rect.left/Tile.LENGTH) - 1,
                   ceil(rect.right/Tile.LENGTH) + 1):
      for y in range(floor(rect.top/Tile.LENGTH) - 1,
                     ceil(rect.bottom/Tile.LENGTH) + 1):
        if x >= 0 and y >= 0 and x < len(self.map[0]) and y < len(self.map):
          tile = self.tiles[self.map[y][x]]
          if id == "solid" and tile.isSolid():
            result.append(tile.getCollRect().move(x*Tile.LENGTH, y*Tile.LENGTH))
          elif id == "spike" and tile.isSpike():
            result.append(
                tile.getDamageRect().move(x*Tile.LENGTH, y*Tile.LENGTH))
          elif ((id == "orb" and tile.id == Tile.ORB)
                or (id == "flag" and tile.id == Tile.FLAG)):
            result.append((
                tile.getCollRect().move(x*Tile.LENGTH, y*Tile.LENGTH),
                x, y))
    return result

  def getCloseSolidCollRects(self, rect):
    return self.getCloseTileCollRects(rect, "solid")

  def getCloseSpikeDamageRects(self, rect):
    return self.getCloseTileCollRects(rect, "spike")

  def getCloseOrbRects(self, rect):
    return self.getCloseTileCollRects(rect, "orb")

  def getCloseFlagRects(self, rect):
    return self.getCloseTileCollRects(rect, "flag")

  def triggerOrb(self, orbX, orbY):
    self.setTile(orbX, orbY, Tile.ORB_HOLDER_ON)
    self.renderer.addSfx(orbX * Tile.LENGTH, orbY * Tile.LENGTH,
                         "orb-holder-activate")

    # Don't deactivate spikes if another orb needs to be turned on nearby.
    for x in range(orbX - 3, orbX + 4):
      for y in range(orbY - 3, orbY + 4):
        tile = self.getTile(x, y)
        if tile is not None and tile.id == Tile.ORB_HOLDER_OFF:
          return

    # Search for the first spike.
    for x in range(orbX, orbX + 10):
      for y in range(orbY, orbY + 10):
        tile = self.getTile(x, y)
        if tile is not None and tile.id == Tile.ORB_SPIKE_U:
          self.eraseOrbSpikesAround(x, y)
          return

  def eraseOrbSpikesAround(self, spikeX, spikeY):
    x = spikeX
    while True:
      tile = self.getTile(x, spikeY)
      if tile is None:
        return
      if tile.id != Tile.ORB_SPIKE_U:
        return
      self.setTile(x, spikeY, Tile.EMPTY)
      self.renderer.addSfx(x * Tile.LENGTH, spikeY * Tile.LENGTH,
                           "orb-spike-off")
      x += 1

  def tick(self):
    for spike in self.rndSpikes:
      if self.renderer.tileIsInView(spike.x, spike.y):
        spike.tick()
