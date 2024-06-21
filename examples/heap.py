from pwn import *
from pyda import *

import pwndbg # must come after pyda import, i think
from termcolor import colored, cprint

import string
import sys

p = process()

e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc.address = p.maps[libc.path].base

sym_map = {
    libc.symbols["malloc"]: "malloc",
    libc.symbols["free"]: "free",
    libc.symbols["realloc"]: "realloc",
}

# todo: use dwarf to figure out where tcache pointer is in tls?
# print(f"dwarf: {libc.dwarf}")

def heap_hook(p):
    name = sym_map[p.regs.rip]

    print(f"{name}(" + ", ".join([
        f"rdi={hex(p.regs.rdi)}",
    ]) + ")")

def after_heap_hook(p):
    heap = pwndbg.heap.current
    tcachebins = heap.tcachebins()
    if tcachebins is not None:
        for (s, b) in tcachebins.bins.items():
            if len(b.fd_chain) < 2:
                continue
            print(f"tcache {colored(hex(s), 'yellow')}: ", end="")
            print(colored(' -> ', 'yellow').join([hex(x) for x in b.fd_chain]))

        print()
    else:
        print("heap not initialized yet?")
    

for sym in sym_map:
    p.hook(sym, heap_hook)
    p.hook_after_call(sym, after_heap_hook)

p.run()