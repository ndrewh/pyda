from pyda import *
from pwnlib.elf.elf import ELF

p = process()

e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

counter = 0
def malloc_counter(p):
    global counter
    counter += 1

p.hook(e.plt["malloc"], malloc_counter)
p.run()

print(f"malloc count: {counter}")
print("pass")
