from libdebug import debugger
from pwnlib.elf.elf import ELF
from pathlib import Path
import sys

bin_path = Path(sys.argv[1])
d = debugger(str(bin_path.resolve()))
r = d.run()

e = ELF(bin_path)

counter = 0
def malloc_counter(t, bp):
    global counter
    counter += 1

d.breakpoint(e.plt["malloc"], callback=malloc_counter, file=bin_path.name)
d.cont()
d.wait()

print(f"malloc count: {counter}")
print("pass")
