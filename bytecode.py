#!/usr/bin/env python
import r2pipe

r2 = r2pipe.open("ch18.bin")

res = []

res.append(r2.cmdj("p8j 1 @ 0x08049b95")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049b96")[0])
res.append(r2.cmdj("p8j 2 @ 0x08049b97")[0])
res.append(r2.cmdj("p8j 2 @ 0x08049b99")[0])
res.append(r2.cmdj("p8j 3 @ 0x08049b9b")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049b9e")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049b9f")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049ba0")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049ba1")[0])
res.append(r2.cmdj("p8j 2 @ 0x08049ba2")[0])
res.append(r2.cmdj("p8j 3 @ 0x08049ba4")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049ba7")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049ba8")[0])
res.append(r2.cmdj("p8j 3 @ 0x08049ba9")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049bac")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049bad")[0])
res.append(r2.cmdj("p8j 2 @ 0x08049bae")[0])
res.append(r2.cmdj("p8j 2 @ 0x08049bb0")[0])
res.append(r2.cmdj("p8j 2 @ 0x08049bb2")[0])
res.append(r2.cmdj("p8j 3 @ 0x08049bb4")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049bb7")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049bb8")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049bb9")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049bba")[0])
res.append(r2.cmdj("p8j 3 @ 0x08049bbb")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049bbe")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049bbf")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049bc0")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049bc1")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049bc2")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049bc3")[0])
res.append(r2.cmdj("p8j 3 @ 0x08049bc4")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049bc7")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049bc8")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049bc9")[0])
res.append(r2.cmdj("p8j 3 @ 0x08049bca")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049bcd")[0])
res.append(r2.cmdj("p8j 2 @ 0x08049bce")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049bd1")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049bd2")[0])
res.append(r2.cmdj("p8j 4 @ 0x08049bd3")[0])
res.append(r2.cmdj("p8j 1 @ 0x08049bd7")[0])


# Load dword
# eax = 0xFFFFFFFF

def parse_instr(hx):
  
  _92 = hx & 0b111
  _91 = (hx >> 3) & 0b111
  _93 = _91 & 0b1
  _94 = _93 >> 1
  _90 = 6 >> hx

  return "[{:02x}, {:02x}, {:02x}, {:02x}, {:02x}]".format(_90, _91, _92, _93, _94)

for hx in res:
  print("{:02x} {}".format(hx, parse_instr(hx)))
