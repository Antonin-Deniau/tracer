class Beacon:
  def __init__(self):
    self.value = None
    self.colors = None

  def get_color(self, color_bool, i):
    if not color_bool:
      self.colors[i] = not self.colors[i]
    return self.colors[i]

  def diff(self, new_value):
    if self.value == None:
      self.value = list(new_value)
      self.colors = [True] * len(new_value)

    res = []

    for i in xrange(len(self.value)):
      color_bool = new_value[i] == self.value[i]
      res.append({ 'value': new_value[i], 'color': self.get_color(color_bool, i) })

    self.value = new_value
    return res

def diff_reg(reg, reg_val, size=16):
  if reg not in vals: vals[reg] = Beacon() 
  t = "{:08x}".format(reg_val)
  return vals[reg].diff(t)

