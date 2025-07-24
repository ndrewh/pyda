from pyda import *
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64
import string
import sys, platform

p = process()

e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

plt_map = { e.plt[x]: x for x in e.plt }

def guess_arg(x):
    printable_chars = bytes(string.printable, 'ascii')

    # Is pointer?
    if x > 0x100000000:
        try:
            data = p.read(x, 0x20)
            if all([c in printable_chars for c in data[:4]]):
                if 0 in data:
                    return str(data[:data.index(0)])
                else:
                    return str(data[:20]) + "..."

        except Exception as e:
            pass

    return hex(x)

def syscall_pre_hook_x86(p, num):
    print(f"[tid {p.tid}] [pre syscall {num}] (" + ", ".join([
        f"rdi={guess_arg(p.regs.rdi)}",
        f"rsi={guess_arg(p.regs.rsi)}",
        f"rdx={guess_arg(p.regs.rdx)}",
        f"rcx={guess_arg(p.regs.rcx)}",
    ]) + ")")

def syscall_pre_hook_arm64(p, num):
    print(f"[tid {p.tid}] [pre syscall {num}] (" + ", ".join([
        f"x0={guess_arg(p.regs.x0)}",
        f"x1={guess_arg(p.regs.x1)}",
        f"x2={guess_arg(p.regs.x2)}",
        f"x3={guess_arg(p.regs.x3)}",
    ]) + ")")

def syscall_post_hook(p, num):
    print(f"[tid {p.tid}] [post syscall {num}]")

syscall_pre_hook = syscall_pre_hook_arm64 if platform.machine() == "aarch64" else syscall_pre_hook_x86

for snum in range(500):
    p.syscall_pre(snum, syscall_pre_hook)

for snum in range(500):
    p.syscall_post(snum, syscall_post_hook)

p.run()
