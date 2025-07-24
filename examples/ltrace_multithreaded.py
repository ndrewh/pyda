# This is basically just ltrace.py but we also print the thread number
# and print a message when threads are created.

from pyda import *
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64
import string
import sys, time

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
    print(f"[thread {p.tid}] {name}(" + ", ".join([
        f"arg0={guess_arg(p.regs.arg1)}",
        f"arg1={guess_arg(p.regs.arg2)}",
        f"arg2={guess_arg(p.regs.arg3)}",
        f"arg3={guess_arg(p.regs.arg4)}",
    ]) + ")")

def thread_entry(p):
    print(f"thread_entry for {p.tid}")

p.set_thread_entry(thread_entry)

for x in e.plt:
    p.hook(e.plt[x], lib_hook)

p.run()