#!/usr/bin/env python
from decode_bytecode import decode
import r2pipe

r2 = r2pipe.open("./ch18.bin")

r2.cmd("e dbg.profile=profile.rr2")

r2.cmd("ood")

addr = 0x8048839
r2.cmd("db {}".format(addr))

res = []
for i in xrange(400):
  r2.cmd("dc")

  bl = r2.cmdj("arj")["ebx"]
  res.append("{:08x}".format(bl & 0xFF))

for line in res: print(line)
