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
                if 0 in data:
                    return str(data[:data.index(0)])
                else:
                    return str(data[:20]) + "..."

        except Exception as e:
            pass
    
    return hex(x)

def syscall_pre_hook(p, num):
    print(f"[syscall {num}] (" + ", ".join([
        f"rdi={guess_arg(p.regs.rdi)}",
        f"rsi={guess_arg(p.regs.rsi)}",
        f"rdx={guess_arg(p.regs.rdx)}",
        f"rcx={guess_arg(p.regs.rcx)}",
    ]) + ")")

for snum in range(500):
    p.syscall_pre(snum, syscall_pre_hook)

p.run()