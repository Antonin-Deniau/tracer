#!/usr/bin/env python
import r2pipe
from tinydb import TinyDB, where
db = TinyDB('./trace.json')
regs_db = db.table('regs')

r2 = r2pipe.open("./ch18.bin")

r2.cmd("e dbg.profile=profile.rr2")

opcodes = [
  0x80488e4, 0x80488c0, 0x804888e,
  0x8048862, 0x8048854, 0x804880a,
  0x80487be, 0x804878d, 0x804875c,
  0x804871e, 0x8048697, 0x8048672,
  0x8048647, 0x804861c, 0x80485f0,
  0x80485bb, 0x8048591, 0x804855b,
  0x8048518, 0x80484d5, 0x804849c,
  0x804846c,
]

r2.cmd("ood")

for opcode in opcodes:
  print("break at {}".format(hex(opcode)))
  r2.cmd("db {}".format(opcode))

r2.cmd("dc")
# for _ in xrange(520):
for _ in xrange(50):
  regs = r2.cmdj("arj")

  eax = regs["eax"]
  edx = regs["edx"]
  ecx = regs["edx"]

  regs_db.insert({ 'eax': eax, 'edx': edx, 'ecx': ecx })

  r2.cmd("dc")
