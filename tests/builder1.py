from pyda import *
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64
import string
import sys

p = process()

e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

plt_map = { e.plt[x]: x for x in e.plt }
def lib_hook(p):
    p.regs.arg2 += 1337

p.builder_hook(e.plt["printf"], lib_hook)

p.run()
