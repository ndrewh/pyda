from pyda import *
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64
import string
import sys, time

p = process()

e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

excepted = False
try:
    p.run()
except FatalSignalError as err:
    assert err.args[0] is not None
    excepted = True
    
    print(err)

assert excepted

print("Exception 1")

# Now, after the exception, redirect execution to main again
p.regs.pc = e.symbols["main"]
excepted = False
try:
    p.run()
except FatalSignalError as err:
    assert err.args[0] is not None
    excepted = True

    print(err)

assert excepted

print("Exception 2")

# Finally, let's try calling out to the function as a callable
excepted = False
try:
    p.callable(e.symbols["segfault"])()
except FatalSignalError as err:
    assert err.args[0] is not None
    excepted = True

    print(err)

assert excepted

print("Exception 3")

p.regs.rsp += 0x18
p.regs.pc = e.symbols["main"] + 0x26
p.run()
print("pass")