import angr

start = 0x40102c
end = 0x40105d
explode = (0x401035, 0x401058)

proj = angr.Project('./test', load_options={'auto_load_libs':False})

state = proj.factory.blank_state(addr=start)

""" Argv symbolisation
argv1 = angr.claripy.BVS("argv1", 41 * 8)
state = proj.factory.entry_state(args=["./lol_so_obfuscated", argv1])
"""

""" Add constraints
state.add_constraints(m >= 0x20)
state.add_constraints(m <= '}')
"""

""" Function arguments symbolisation
for i in xrange(2):
  state.stack_push(state.se.BVS('int_{}'.format(i), 4*8))
"""

""" Register set
state.regs.rdi = 0x0
"""

path = proj.factory.path_group(state)
ex = path.explore(find=end, avoid=explode)

if ex.found:
  found = ex.found[0].state

  """ BVS Desymbolisation
  res = found.se.any_str(password)
  """

  """ Function args desymbolisation
  found.stack_pop()
 
  answer = []
  ints = found.se.any_int(found.stack_pop())

  answer.append(str(ints & 0xffffffff))
  answer.append(str(ints >> 32))
  """

  print(" ".join(answer))
