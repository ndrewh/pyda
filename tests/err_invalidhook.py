from pyda import *
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64
import string
import sys, time

p = process()

e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

counter = 0
def lib_hook(p):
    global counter
    counter += 1

p.hook(0x1337133713371337, lib_hook)
p.run()