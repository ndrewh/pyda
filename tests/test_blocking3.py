from pyda import *
from pwnlib.elf.elf import ELF

p = process()

e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

plt_map = { e.plt[x]: x for x in e.plt }

counter2 = 0
p.run_until(e.plt["malloc"])
p.run_until(e.plt["malloc"])
p.run_until(e.plt["malloc"])
p.run_until(e.plt["malloc"])

# NOTE: p.run() is not called -- process should finish and print an error