from pyda import *
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64
import time

p = process(io=True)

e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

p.run_until(e.symbols["main"])

lol = p.callable(e.symbols["lol"])
st1 = b"abcd"
st2 = b"A" * 0x400

lol(st1, 1337)
p.recvuntil(b"lol abcd 1337")
lol(st2, 1338)
p.recvuntil(b"lol " + b"A" * 0x400 + b" 1338")
lol(st1, 1339)
p.recvuntil(b"lol abcd 1339")
lol(st1, 1340)
p.recvuntil(b"lol abcd 1340")
p.run()
print("pass")