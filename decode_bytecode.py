#!/usr/bin/env python
from unicorn import *
from unicorn.x86_const import *

ADDRESS = 0x8000
FUNCTION_ADDR = 0x8F0
FUNCTION_LEN = 56

def decode(val):
  with open("./ch18.bin", "rb") as binary_file:
    code = binary_file.read()

    res = []

    def hook_mem_access(uc, access, address, size, value, user_data):
      if address == 0x8049a90 or address == 0x8049a91 or address == 0x8049a92 or address == 0x8049a93 or address == 0x8049a94:
        res.append(value)

    mu = Uc(UC_ARCH_X86, UC_MODE_32)

    mu.mem_map(ADDRESS, 512 * 1024 * 1024)
    mu.mem_write(ADDRESS, code)
    mu.reg_write(UC_X86_REG_EAX, val)

    mu.reg_write(UC_X86_REG_ESP, ADDRESS + 512 * 1024 * 1024)

    mu.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, hook_mem_access)

    mu.emu_start(ADDRESS + FUNCTION_ADDR, ADDRESS + FUNCTION_ADDR + FUNCTION_LEN)

    return res
