from pyda import *
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64
import time

def fix_buffering(p):
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    libc.address = p.maps[libc.path].base

    stdin = u64(p.read(libc.symbols["stdin"], 8))
    stdout = u64(p.read(libc.symbols["stdout"], 8))
    stderr = u64(p.read(libc.symbols["stderr"], 8))
    p.callable(libc.symbols["setvbuf"])(stdin, 0, 2, 0)
    p.callable(libc.symbols["setvbuf"])(stdout, 0, 2, 0)
    p.callable(libc.symbols["setvbuf"])(stderr, 0, 2, 0)

p = process(io=True)

e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

p.run_until(e.symbols["main"])
fix_buffering(p)

p.recvuntil(b"please enter your name:")
p.sendline(b"A" * 100000000)
p.recvline()
line = p.recvline()
expected = b"hello, " + b"A" * 100000000 + b"\n"
assert line == expected, f"bad {len(line)} {len(expected)}"

p.run()
print("pass")