#!/usr/bin/env python
import r2pipe

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

match = {
  'op1': 0x80488e4,
  'op2': 0x80488c0,
  'op3': 0x804888e,
  'op4': 0x8048862,
  'op5': 0x8048854,
  'op6': 0x804880a,
  'op7': 0x80487be,
  'op8': 0x804878d,
  'op9': 0x804875c,
  'op10': 0x804871e,
  'op11': 0x8048697,
  'op12': 0x8048672,
  'op13': 0x8048647,
  'op14': 0x804861c,
  'op15': 0x80485f0,
  'op16': 0x80485bb,
  'op17': 0x8048591,
  'op18': 0x804855b,
  'op19': 0x8048518,
  'op20': 0x80484d5,
  'op21': 0x804849c,
  'op22': 0x804846c,
}

r2.cmd("ood")

for opcode in opcodes:
  print("break at {}".format(hex(opcode)))
  r2.cmd("db {}".format(opcode))

res = ""

r2.cmd("dc")
for _ in xrange(520):
  name = "unk"
  addr = r2.cmdj("arj")["eip"]

  _90 = r2.cmdj("p8j 1 @ 0x8049a90")[0]
  _91 = r2.cmdj("p8j 1 @ 0x8049a91")[0]
  _92 = r2.cmdj("p8j 1 @ 0x8049a92")[0]
  _93 = r2.cmdj("p8j 1 @ 0x8049a93")[0]
  _94 = r2.cmdj("p8j 1 @ 0x8049a94")[0]

  for key in match:
    if match[key] == addr:
      name = key
      break

  res += "{:02x} {:02x} {:02x} {:02x} {:02x} {}\n".format(_90, _91, _92, _93, _94, name)

  r2.cmd("dc")

print(res)
