from pyda import *
from pwnlib.elf.elf import ELF

p = process()

e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

plt_map = { e.plt[x]: x for x in e.plt }

counter2 = 0
try:
    while True:
        p.run_until(e.plt["malloc"])
        counter2 += 1
except ThreadExitError:
    pass

assert counter2 == 20
print("pass")