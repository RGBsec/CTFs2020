from Sprite import Sprite

class SFX(Sprite):

  def __init__(self, renderer, x, y, animation):
    super(SFX, self).__init__(
        renderer, "SFX", animation, Sprite.RIGHT, x, y, 0, {})

  def render(self, display, cameraX, cameraY):
    super(SFX, self).render(display, cameraX, cameraY)
    if self.finishedAnimation():
      self.kill()
