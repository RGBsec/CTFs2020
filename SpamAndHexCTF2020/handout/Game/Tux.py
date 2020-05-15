from Sprite import Sprite
from Enemy import Enemy
from Tile import Tile
from pygame import Rect

class Tux(Enemy):
  def __init__(self, renderer, map, playerGroup, x, y):
    super(Tux, self).__init__(
        renderer, map, playerGroup, 'Tux',
        x, y, Rect(4, 2, 22, 30), 4, 2, 32, {})
    self.t = 0
    self.setDirection(Sprite.LEFT)

  def isAboutToFallDown(self):
    if not self.moving:
      return False

    rect = self.getCollRect()
    if self.direction == Sprite.RIGHT:
      rect = rect.move(Tile.LENGTH, 0)
    else:
      rect = rect.move(-Tile.LENGTH, 0)
    for tileRect in self.map.getCloseSolidCollRects(rect):
      if rect.colliderect(
          Rect(tileRect.x, tileRect.top-1, tileRect.width, 2)):
        return False

    return True


  def tick(self):
    def dont():
      self.stopMoving()
      self.t = 0

    super(Tux, self).tick()

    if self.isImmobile():
      return

    self.t += 1
    if self.t == 60:
      if self.direction == Sprite.RIGHT:
        self.setDirection(Sprite.LEFT)
      else:
        self.setDirection(Sprite.RIGHT)
      self.startMoving()
    elif self.t == 90:
      self.stopMoving()
    elif self.t == 150:
      self.t = 0

    if self.isAboutToFallDown():
      dont()

    if self.moving:
      self.changeAnimation("walk")
    else:
      self.changeAnimation("idle")
