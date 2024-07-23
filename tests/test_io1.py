from pyda import *
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64

p = process(io=True)

e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

def main_hook(p):
    print(f"at main, rsp={hex(p.regs.rsp)}")
    return_addr = p.read(p.regs.rsp, 8)
    print(f"return address: {hex(u64(return_addr))}")

p.hook(e.symbols["main"], main_hook)

p.recvuntil(b"please enter your name:")
p.sendline("andrew")
p.recvuntil("please enter your age:")
p.sendline("21")
p.recvline()
line = p.recvline()
assert line == b"hello andrew, you are 21 years old\n", line
p.run()
print("pass")