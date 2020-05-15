from Sprite import Sprite
from Enemy import Enemy
from Tile import Tile
from pygame import Rect
from math import floor

class TRex(Enemy):
  BASE_SPEED = 4
  NORMAL_DAMAGE_RECTS = [Rect(30, 40, 36, 64), Rect(50, 10, 48, 38),
                         Rect(10, 40, 20, 32)]
  RUN_DAMAGE_RECTS = [Rect(20, 46, 107, 44), Rect(8, 44, 12, 24)]

  def __init__(self, renderer, map, rnd, playerGroup, x, y):
    super(TRex , self).__init__(
        renderer, map, playerGroup, 'T-Rex',
        x, y, Rect(30, 40, 36, 64),
        TRex.BASE_SPEED, 20, 96, {}
    )
    self.rnd = rnd
    self.damageRects = TRex.NORMAL_DAMAGE_RECTS
    self.setDirection(Sprite.LEFT)
    self.playerEntered = False
    self.t = 30

  def isImmobile(self):
    # Not immobile if damaged. Immobile if player isn't near.
    return self.dead

  def startWalking(self):
    self.moving = True
    self.speed = TRex.BASE_SPEED
    self.damageRects = TRex.NORMAL_DAMAGE_RECTS

  def startRunning(self):
    self.moving = True
    self.speed = TRex.BASE_SPEED * 2
    self.damageRects = TRex.RUN_DAMAGE_RECTS

  def stopMoving(self):
    self.moving = False
    self.speed = TRex.BASE_SPEED
    self.damageRects = TRex.NORMAL_DAMAGE_RECTS

  def isWalking(self):
    return self.moving and self.speed == TRex.BASE_SPEED

  def isRunning(self):
    return self.moving and self.speed == TRex.BASE_SPEED * 2

  def die(self):
    super(TRex, self).die()
    self.t = 30
    self.explodeCount = 0

  def changeAnimation(self, animation):
    stayOnSameFrame = self.animation == animation
    if self.isDamaged() and self.damageTimer > 5:
      animation = "d-" + animation
    super(TRex, self).changeAnimation(animation, stayOnSameFrame)
    self.prevIsDamaged = self.isDamaged()

  def damage(self, amount):
    super(TRex, self).damage(amount)
    self.changeAnimation(self.animation)

  def tick(self):
    super(TRex, self).tick()

    if self.dead:
      if self.explodeCount == 30:
        rect = self.getCollRect()
        self.map.renderer.addSfx(rect.centerx - 60, rect.centery - 80,
                                 "explosion-2")
        self.map.setTile(floor(rect.centerx / Tile.LENGTH),
                         floor(rect.centery / Tile.LENGTH),
                         Tile.FLAG)
        self.kill()
        return
      self.t -= 1
      if self.t <= 0:
        self.t = 3
        rect = self.getCollRect()
        self.map.renderer.addSfx(rect.centerx + self.rnd.randint(-55, 15),
                                 rect.centery + self.rnd.randint(-65, 15),
                                 "explosion")
        self.explodeCount += 1


    if self.isImmobile():
      return

    playerRect = None
    for player in self.playerGroup.sprites():
      playerRect = player.getCollRect()

    # Don't do anything if the player is not in the arena yet.
    if (not self.playerEntered and playerRect is not None
        and playerRect.centerx >= 2950):
      self.playerEntered = True
    if self.playerEntered:
      self.t -= 1
      if self.t <= 0:
        self.t = self.rnd.randint(30, 60)
        if playerRect is None:
          self.stopMoving()
        elif self.moving:
          self.stopMoving()
        else:
          # Face the player.
          if playerRect.centerx < self.getCollRect().centerx:
            self.setDirection(Sprite.LEFT)
          else:
            self.setDirection(Sprite.RIGHT)

          if self.rnd.randint(0, 100) < 50:
            self.startWalking()
          else:
            self.startRunning()

    if self.isWalking():
      self.changeAnimation("walk")
    elif self.isRunning():
      self.changeAnimation("run")
    else:
      self.changeAnimation("idle")
