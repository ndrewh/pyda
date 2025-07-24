from pyda import *
from pyda.compiler import Global
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64
import string
import sys
import ctypes
from pwnlib.asm import asm
import time

p = process()

e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

plt_map = { e.plt[x]: x for x in e.plt }

counter = Global(ctypes.c_long(0))
buf = Global((ctypes.c_long * 0x1000)())

def lib_hook(b):
    counter.val += 1
    buf[counter % 4] = 5

p.builder_hook(e.address + 0x1056, lib_hook)
p.run()

print(counter)
print(buf.cval[:8])
print("pass")
