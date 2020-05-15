# Custom random generator that's deterministic.
class Rnd(object):

  def __init__(self, input):
    self.input = input
    self.val = 4
    pass

  def randint(self, min, max):
    # LCG influenced by the keypresses.
    num = self.input.getKeysPressed().asNumber()

    for i in range(num + 1):
      self.val = ((self.val * 1103515245) + 12345) & 0x7fffffff

    return (self.val % (max - min + 1)) + min
