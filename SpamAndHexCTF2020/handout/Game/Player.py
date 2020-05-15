from Sprite import Sprite
from Entity import Entity
from Tile import Tile
from Input import KeysPressed
from pygame import Rect
from pygame.sprite import Group
from math import floor
from copy import copy
import pygame

class Player(Entity):
  def __init__(self, renderer, input, map, enemyGroup, x, y):
    super(Player, self).__init__(
        renderer, map, 'Android', x, y, Rect(20, 18, 26, 32),
        4, 8, 66, {'die': (4, -2)})
    self.renderer = renderer
    self.input = input
    self.enemyGroup = enemyGroup
    self.damagedEnemyGroup = Group()
    self.prevKeysPressed = KeysPressed()
    self.keysPressed = KeysPressed()
    self.invulnerableTimer = 0
    self.attackTimer = 0
    self.crouching = False
    self.holdingOrb = False
    self.holdingFlagTimer = 0

  def handleKeypresses(self):
    self.prevKeysPressed = copy(self.keysPressed)
    self.keysPressed = self.input.getKeysPressed()

    if self.isImmobile():
      return

    if ((self.keysPressed.right or self.keysPressed.left)
        and self.keysPressed.down):
      self.placeOrbOnStand()
    if self.keysPressed.up and not self.prevKeysPressed.up:
      self.jump()
    if self.keysPressed.down and not self.prevKeysPressed.down:
      self.startCrouching()
    elif not self.keysPressed.down and self.prevKeysPressed.down:
      self.stopCrouching()
    if self.keysPressed.space and not self.prevKeysPressed.space:
      self.attack()
    if self.keysPressed.right:
      if self.canWalk():
        self.setDirection(Sprite.RIGHT)
        self.startMoving()
    if self.keysPressed.left:
      if self.canWalk():
        self.setDirection(Sprite.LEFT)
        self.startMoving()
    if not self.keysPressed.left and not self.keysPressed.right:
      self.stopMoving()

  def canWalk(self):
    if self.isImmobile():
      return False
    if self.isAttacking() and self.onGround:
      return False
    return True

  def isImmobile(self):
    return self.isHoldingFlag() or super(Player, self).isImmobile()

  def isHoldingFlag(self):
    return self.holdingFlagTimer > 0

  def startFalling(self):
    if self.onGround:
      self.attackTimer = 0
    super(Player, self).startFalling()

  def stopFalling(self):
    if not self.onGround:
      self.attackTimer = 0
    super(Player, self).stopFalling()

  def damage(self, amount):
    if self.invulnerableTimer > 0:
      return
    super(Player, self).damage(amount)
    if not self.dead:
      self.invulnerableTimer = 45
      self.attackTimer = 0
    self.dropOrb()

  def jump(self):
    if self.onGround and not self.isAttacking():
      self.onGround = False
      self.fallSpeed = -20

  def startCrouching(self):
    if not self.crouching and self.onGround:
      self.crouching = True
      self.attackTimer = 0
      self.collRect = Rect(20, 32, 26, 18)

  def stopCrouching(self):
    if self.crouching:
      self.crouching = False
      self.collRect = Rect(20, 18, 26, 32)

  def attack(self):
    # Can only attack once when in the air
    if not self.onGround and self.isAttacking():
      return
    # Can attack twice on the ground
    if self.onGround:
      if self.isAttacking():
        if self.animation.endswith("attack-1"):
          self.setAnimation("attack-2")
        else:
          return

    self.stopMoving()
    self.stopCrouching()
    self.attackTimer = 15
    self.damagedEnemyGroup.empty()

  def isAttacking(self):
    return self.attackTimer > 0

  def changeAnimation(self, animation):
    if self.holdingOrb:
      animation = "h-" + animation
    super(Player, self).changeAnimation(animation)

  def updateAnimation(self):
    if self.damageTimer != 0:
      # Damage animation handled in Entity.
      return

    if self.isHoldingFlag():
      self.changeAnimation("hold-flag")
    elif self.onGround:
      if self.moving:
        if self.crouching:
          self.changeAnimation("crouch-walk")
        else:
          self.changeAnimation("walk")
      elif self.isAttacking():
        if self.animation.endswith("attack-2"):
          self.changeAnimation("attack-2")
        else:
          self.changeAnimation("attack-1")
      elif self.crouching:
        self.changeAnimation("crouch")
      else:
        self.changeAnimation("idle")
    else:
      if self.isAttacking():
        self.changeAnimation("jump-attack")
      elif self.fallSpeed > 0:
        self.changeAnimation("jump-down")
      else:
        self.changeAnimation("jump-up")

  def pickUpNearbyOrb(self):
    if (not self.holdingOrb and not self.isDamaged()
        and self.invulnerableTimer == 0):
      rect = self.getCollRect()
      for data in self.map.getCloseOrbRects(rect):
        orbRect, x, y = data
        if rect.colliderect(orbRect):
          self.map.setTile(x, y, Tile.EMPTY)
          self.holdingOrb = True
          break

  def pickUpNearbyFlag(self):
    rect = self.getCollRect()
    for data in self.map.getCloseFlagRects(rect):
      flagRect, x, y = data
      if rect.colliderect(flagRect):
        self.map.setTile(x, y, Tile.EMPTY)
        self.holdingFlagTimer = 1
        break

  def dropOrb(self):
    if not self.holdingOrb:
      return

    self.holdingOrb = False
    rect = self.getCollRect()
    offsets = [(0, 0), (1, 0), (-1, 0), (0, 1), (0, -1)]
    midX = floor(rect.centerx / Tile.LENGTH)
    midY = floor(rect.centery / Tile.LENGTH)
    for offset in offsets:
      x = midX + offset[0]
      y = midY + offset[1]
      tile = self.map.getTile(x, y)
      if tile is not None and tile.id == Tile.EMPTY:
        self.map.setTile(x, y, Tile.ORB)
        break

  def placeOrbOnStand(self):
    if self.isImmobile():
      return
    if self.isAttacking() or not self.onGround:
      return False
    if not self.holdingOrb:
      return

    rect = self.getCollRect()
    offsets = [(0, 0), (1, 0), (-1, 0)]
    midX = floor(rect.centerx / Tile.LENGTH)
    midY = floor(rect.centery / Tile.LENGTH)
    for offset in offsets:
      x = midX + offset[0]
      y = midY + offset[1]
      tile = self.map.getTile(x, y)
      if tile is not None and tile.id == Tile.ORB_HOLDER_OFF:
        tileRect = tile.getCollRect().move(x*Tile.LENGTH, y*Tile.LENGTH)
        if ((tileRect.centerx > rect.centerx and self.keysPressed.right)
            or (tileRect.centerx < rect.centerx and self.keysPressed.left)):
          self.map.triggerOrb(x, y)
          self.holdingOrb = False

  def tick(self):
    self.handleKeypresses()

    super(Player, self).tick()

    if self.dead:
      self.visible = True
      return

    self.pickUpNearbyOrb()
    self.pickUpNearbyFlag()

    if self.holdingFlagTimer > 0:
      self.holdingFlagTimer += 1

    if self.invulnerableTimer > 0:
      self.invulnerableTimer -= 1
      if self.damageTimer == 0:
        self.visible = (self.invulnerableTimer / 2) % 2
    else:
      self.visible = True

    if not self.onGround:
      self.stopCrouching()

    if self.attackTimer > 0:
      self.attackTimer -= 1
      if self.direction == Sprite.RIGHT:
        attackRect = self.getCollRect().move(10, 0)
      else:
        attackRect = self.getCollRect().move(-10, 0)
      for enemy in self.enemyGroup.sprites():
        for rect in enemy.getDamageRects():
          if attackRect.colliderect(rect):
            # Every enemy should only be damaged once per attack.
            if enemy not in self.damagedEnemyGroup:
              enemy.damage(1)
              self.damagedEnemyGroup.add(enemy)
              break

    self.renderer.updateCamera(self.getCollRect())
    self.updateAnimation()
