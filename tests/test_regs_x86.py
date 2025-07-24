from pyda import *
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64

p = process()

e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

def main_hook(p):
    # get all the registers
    print(f"reg rax: {hex(p.regs.rax)}")
    print(f"reg rbx: {hex(p.regs.rbx)}")
    print(f"reg rcx: {hex(p.regs.rcx)}")
    print(f"reg rdx: {hex(p.regs.rdx)}")
    print(f"reg rsi: {hex(p.regs.rsi)}")
    print(f"reg rdi: {hex(p.regs.rdi)}")
    print(f"reg rbp: {hex(p.regs.rbp)}")
    print(f"reg rsp: {hex(p.regs.rsp)}")
    print(f"reg rip: {hex(p.regs.pc)}")
    print(f"reg pc: {hex(p.regs.pc)}")
    print(f"reg r8: {hex(p.regs.r8)}")
    print(f"reg r9: {hex(p.regs.r9)}")
    print(f"reg r10: {hex(p.regs.r10)}")
    print(f"reg r11: {hex(p.regs.r11)}")
    print(f"reg r12: {hex(p.regs.r12)}")
    print(f"reg r13: {hex(p.regs.r13)}")
    print(f"reg r14: {hex(p.regs.r14)}")
    print(f"reg r15: {hex(p.regs.r15)}")
    print(f"reg xmm0: {hex(p.regs.xmm0)}")
    print(f"reg xmm1: {hex(p.regs.xmm1)}")
    print(f"reg xmm2: {hex(p.regs.xmm2)}")
    print(f"reg xmm3: {hex(p.regs.xmm3)}")
    print(f"reg xmm4: {hex(p.regs.xmm4)}")
    print(f"reg xmm5: {hex(p.regs.xmm5)}")
    print(f"reg xmm6: {hex(p.regs.xmm6)}")
    print(f"reg xmm7: {hex(p.regs.xmm7)}")
    print(f"reg fsbase: {hex(p.regs.fsbase)}")

    assert p.regs.pc == p.regs.pc
    assert p.regs.pc != 0

    # try round-trip
    p.regs.rax = 0xdeadbeef
    assert p.regs.rax == 0xdeadbeef

    p.regs.xmm0 = 0xdeadbeefdeadbeefdeadbeefdeadbeef
    assert p.regs.xmm0 == 0xdeadbeefdeadbeefdeadbeefdeadbeef

    print("success")



p.hook(e.symbols["main"], main_hook)
p.run()