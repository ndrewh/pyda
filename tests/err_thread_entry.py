from pyda import *
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64
import string
import sys, time

p = process()

e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

plt_map = { e.plt[x]: x for x in e.plt }

counter = 0
def lib_hook(p):
    name = plt_map[p.regs.pc]
    print(f"[thread {p.tid}] {name}")

def thread_entry(p):
    global counter
    print(f"thread_entry for {p.tid}")

    counter += 1
    if counter == 2:
        jsdkfjdsaklfadska

p.set_thread_entry(thread_entry)

for x in e.plt:
    p.hook(e.plt[x], lib_hook)

p.run()
