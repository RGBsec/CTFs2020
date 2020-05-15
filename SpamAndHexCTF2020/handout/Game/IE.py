from Sprite import Sprite
from Enemy import Enemy
from pygame import Rect

class IE(Enemy):
  def __init__(self, renderer, map, playerGroup, x, y):
    super(IE, self).__init__(
        renderer, map, playerGroup, 'IE',
        x, y, Rect(23, 18, 30, 22), 4, 1, 76, {})
    self.t = 0
    self.flying = True

  def tick(self):
    super(IE, self).tick()

    if self.isImmobile():
      return

    self.t += 1
    if self.t == 60:
      self.setDirection(Sprite.LEFT)
      self.startMoving()
    elif self.t == 90:
      self.stopMoving()
    elif self.t == 150:
      self.setDirection(Sprite.RIGHT)
      self.startMoving()
    elif self.t == 180:
      self.stopMoving()
      self.t = 0
