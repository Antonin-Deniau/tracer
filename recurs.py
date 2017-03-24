#!/usr/bin/env python
import r2pipe

r2 = r2pipe.open("./ch18.bin")

r2.cmd("aaaaa")

start = 0x0804843c
ret = (0x080486be, )

ends = r2.cmdj("axtj {}".format(0x080488eb))

for addr in ends:
    end = addr["from"]
