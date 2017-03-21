#!/usr/bin/env python
import r2pipe

r2 = r2pipe.open("./ch18.bin")

r2.cmd("e dbg.profile=profile.rr2")

r2.cmd("ood")

r2.cmd("db {}".format(0x08048441))

def parse_instr(hx):
  _92 = hx & 0b111
  _91 = (hx >> 3) & 0b111
  _93 = _91 & 0b1
  _94 = _93 >> 1
  _90 = 6 >> hx

  return "[{:02x}, {:02x}, {:02x}, {:02x}, {:02x}]".format(_90, _91, _92, _93, _94)

res = ""

r2.cmd("dc")
# for _ in xrange(520):
for _ in xrange(20):
  regs = r2.cmdj("arj")

  esi = regs["esi"] # EIP

  _90 = r2.cmdj("p8j 1 @ 0x8049a90")[0]
  _91 = r2.cmdj("p8j 1 @ 0x8049a91")[0]
  _92 = r2.cmdj("p8j 1 @ 0x8049a92")[0]
  _93 = r2.cmdj("p8j 1 @ 0x8049a93")[0]
  _94 = r2.cmdj("p8j 1 @ 0x8049a94")[0]

  op = r2.cmdj("p8j 4 @ {}".format(esi))[0]

  fmt =  "{:08x} => {:02x} [{:02x}, {:02x}, {:02x}, {:02x}, {:02x}] {}\n"
  res += fmt.format(esi, op, _90, _91, _92, _93, _94, parse_instr(op))

  r2.cmd("dc")

print(res)
