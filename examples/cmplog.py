from pyda import *
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64, u32
import string
import sys
import subprocess
from collections import defaultdict

p = process()

e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

plt_map = { e.plt[x]: x for x in e.plt }

def get_cmp(proc):
    p = subprocess.run(f"objdump -M intel -d {proc.exe_path} | grep cmp", shell=True, capture_output=True)

    output = p.stdout.decode()
    cmp_locs = {}
    for l in output.split("\n"):
        if len(l) <= 1:
            continue

        # TODO: memory cmp
        if "QWORD PTR" in l:
            continue

        if ":\t" not in l:
            continue

        cmp_locs[int(l.split(":")[0].strip(), 16)] = l.split()[-1]

    return cmp_locs

cmp_locs_unfiltered = get_cmp(p)
cmp_locs = {}
for (a, v) in cmp_locs_unfiltered.items():
    info = v.split(",")
    if len(info) != 2:
        continue
    if "[" in info[0] or "[" in info[1]:
        continue

    if "0x" in info[0] or "0x" in info[1]:
        continue

    cmp_locs[a] = info

print(f"cmp_locs: {len(cmp_locs)}")

eq_count = 0
neq_count = 0
reg_map = {
    "eax": "rax",
    "ebx": "rbx",
    "ecx": "rcx",
    "edx": "rdx",
    "esi": "rsi",
    "edi": "rdi",
    "ebp": "rbp",
    "esp": "rsp",
    "r8d": "r8",
}

counts_by_pc = defaultdict(int)
good_cmps = defaultdict(int)
def cmp_hook(p):
    global eq_count, neq_count
    info = cmp_locs[p.regs.pc - e.address]

    counts_by_pc[p.regs.pc - e.address] += 1

    reg1 = reg_map.get(info[0], info[0])
    reg2 = reg_map.get(info[1], info[1])
    r1 = p.regs[reg1]
    r2 = p.regs[reg2]
    eq = r1 == r2

    if eq:
        eq_count += 1
    else:
        neq_count += 1

    print(f"cmp @ {hex(p.regs.rip - e.address)} {reg1}={hex(r1)} {reg2}={hex(r2)} {eq}")

for x in cmp_locs:
    p.hook(e.address + x, cmp_hook)

p.run()
