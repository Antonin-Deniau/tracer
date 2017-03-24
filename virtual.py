#!/usr/bin/env python
from unicorn import *
from unicorn.x86_const import *
import r2pipe

r2 = r2pipe.open("./ch18.bin")

ADDRESS = 0x08048000
FUNCTION_ADDR = 0x3e0 
FUNCTION_LEN = 1295

# ERRORS
def hook_mem_invalid(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE_UNMAPPED:
        print(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x" %(address, size, value))
    else:
        print(">>> Missing memory is being READ at 0x%x, data size = %u, data value = 0x%x" %(address, size, value))

def hook_unmaped(uc, access, address, size, value, user_data):
    print(">>> Unmapped memory at 0x%x, data size = %u, data value = 0x%x" %(address, size, value))


# MEM ACCESS
def hook_mem_read(uc, access, address, size, value, user_data):
    print("READ {:08x} => {:08x}".format(address, value))

def hook_mem_write(uc, access, address, size, value, user_data):
    print("WRITE {:08x} => {:08x}".format(address, value))

def get_string(addr):
    strings = r2.cmdj("izj")
    print(hex(addr))

    return filter(lambda e: e["vaddr"] == addr, strings)[0]["string"]

# CODE TRACE
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))

    if address == 0x080488eb:
        uc.emu_stop()

    if address == 0x08048a5c: # printf
        esp = uc.reg_read(UC_X86_REG_ESP)
        print(hex(esp))

        string_addr = uc.mem_read(esp + 4, 8)

        string = get_string(string_addr)

        print(string)

        ret_addr = uc.mem_read(esp, 8)

        uc.reg_write(UC_X86_REG_EIP, ret_addr)
        uc.reg_write(UC_X86_REG_ESP, esp + 8)

with open("./ch18.bin", "rb") as binary_file:
    code = binary_file.read()

    mu = Uc(UC_ARCH_X86, UC_MODE_32)

    mu.mem_map(ADDRESS, 512 * 1024 * 1024)
    mu.mem_write(ADDRESS, code)

    mu.reg_write(UC_X86_REG_EAX, 1)
    mu.reg_write(UC_X86_REG_ESI, 0x9a95)
    mu.reg_write(UC_X86_REG_ECX, 0xA)
    mu.reg_write(UC_X86_REG_ESP, ADDRESS + 256 * 1024 * 1024)

    mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
    mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)

    mu.hook_add(UC_HOOK_CODE, hook_code)

    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)
    mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, hook_unmaped)

    mu.emu_start(ADDRESS + FUNCTION_ADDR, ADDRESS + FUNCTION_ADDR + FUNCTION_LEN)
