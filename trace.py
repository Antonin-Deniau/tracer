#!/usr/bin/env python
from decode_bytecode import decode
import r2pipe

r2 = r2pipe.open("./ch18.bin")

r2.cmd("e dbg.profile=profile.rr2")

r2.cmd("ood")

conds = [ 0x08048443, 0x08048450, 0x08048459, 0x08048471, 0x080484a1, 0x080484aa,
0x080484da, 0x0804851d, 0x0804852a, 0x08048533, 0x08048560, 0x08048569, 0x08048596,
0x080485c0, 0x080485c9, 0x080485f5, 0x08048621, 0x0804864c, 0x08048677, 0x0804869c,
0x080486a5, 0x080486ae, 0x080486c8, 0x080486ed, 0x08048723, 0x08048730, 0x08048761,
0x08048792, 0x080487c3, 0x080487cc, 0x0804880f, 0x0804881c, 0x0804882b, 0x08048867,
0x08048870, 0x08048890, 0x08048899, 0x080488c2 ]

start = 0x08048441

for addr in conds:
  r2.cmd("db {}".format(addr))

r2.cmd("db {}".format(start))

res = []
for i in xrange(150):
  r2.cmd("dc")

  pos = r2.cmdj("arj")["eip"]

  if pos == start:
    stack = ""
    eax = r2.cmdj("arj")["eax"]
    line = "0x{:08x} => {}".format(eax, decode(eax))
    res.append(line)
  else: 
    stack = stack + "  "
    instr = r2.cmdj("pdj 1")[0]["opcode"]
    line = stack + " " + instr
    res.append(line)
 

for line in res: print(line)

#0x610100c3 => [3, 0, 0, 0, 3]
#0x20260000 => [0, 0, 0, 0, 0]
#0x3e202600 => [0, 0, 0, 0, 0]
#0x003e2026 => [6, 4, 0, 2, 0]
#0x4201003e => [6, 7, 1, 3, 0]
#0x87014201 => [1, 0, 0, 0, 0]
#0x03023c87 => [7, 0, 0, 0, 2]
#0xfe03023c => [4, 7, 1, 3, 0]
#0xfffe0302 => [2, 0, 0, 0, 0]
#0xc2fffe03 => [3, 0, 0, 0, 0]
#0x13c2fffe => [6, 7, 1, 3, 3]
#0x3c0113c2 => [2, 0, 0, 0, 3]
#0x0109c225 => [5, 4, 0, 2, 0]
#0x000109c2 => [2, 0, 0, 0, 3]
#0x03023c87 => [7, 0, 0, 0, 2]
