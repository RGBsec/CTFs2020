from Entity import Entity
from Sprite import Sprite
import pygame

class Enemy(Entity):
  def __init__(self, renderer, map, playerGroup, graphic, x, y, rect,
               speed, health, flipAdjustment, animationAdjustments):
    super(Enemy, self).__init__(renderer, map, graphic, x, y, rect, speed,
                                health, flipAdjustment, animationAdjustments)
    self.playerGroup = playerGroup
    self.damageRects = [rect]

  def getDamageRects(self):
    result = []
    collRect = self.getCollRect()
    for rect in self.damageRects:
      rect = rect.move(self.x, self.y)
      if self.direction == Sprite.LEFT:
        # Flip the damage rect.
        rect.right = collRect.centerx - (rect.left - collRect.centerx)
      result.append(rect)
    return result

  def tick(self):
    super(Enemy, self).tick()
    if self.isImmobile():
      return
    # Damage the player on collision.
    for rect in self.getDamageRects():
      for player in self.playerGroup.sprites():
        if player.getCollRect().colliderect(rect):
          # Don't damage the player if they're facing the enemy and attacking.
          if player.isAttacking():
            if (player.direction == Sprite.RIGHT
                and player.getCollRect().centerx < self.getCollRect().centerx):
              continue
            if (player.direction == Sprite.LEFT
                and player.getCollRect().centerx > self.getCollRect().centerx):
              continue
          player.damage(1)
