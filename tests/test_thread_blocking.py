from pyda import *
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64
from pwnlib.util.fiddling import hexdump
import string
import sys, time

p = process()

e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

def thread_entry(p):
    print("Thread entry")
    try:
        while True:
            p.run_until(e.symbols["malloc"])
            print(f"[thread {p.tid}] malloc")
    except ThreadExitError:
        print("thread exit error")
        pass

p.set_thread_entry(thread_entry)
p.run()
print("pass")