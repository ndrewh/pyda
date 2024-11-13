from pyda import *
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64
import string
import sys

p = process()

e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

plt_map = { e.plt[x]: x for x in e.plt }

def guess_arg(x):
    printable_chars = bytes(string.printable, 'ascii')

    # Is pointer?
    if x > 0x100000000:
        try:
            data = p.read(x, 0x20)
            if all([c in printable_chars for c in data[:4]]):
                return str(data[:data.index(0)])
        except:
            pass
    
    return hex(x)

def lib_hook(p):
    name = plt_map[p.regs.pc]
    print(f"{name}(" + ", ".join([
        f"rdi={guess_arg(p.regs.arg1)}",
        f"rsi={guess_arg(p.regs.arg2)}",
        f"rdx={guess_arg(p.regs.arg3)}",
        f"rcx={guess_arg(p.regs.arg4)}",
    ]) + ")")

for x in e.plt:
    p.hook(e.plt[x], lib_hook)

p.run()
