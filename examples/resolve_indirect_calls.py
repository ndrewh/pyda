from pyda import *
import sys
import subprocess

p = process()

BASE = p.maps[p.exe_path].base

def u64(data):
    return int.from_bytes(data, "little")

def get_calls(proc):
    p = subprocess.run(f"objdump -M intel -d {proc.exe_path} | grep call", shell=True, capture_output=True)

    output = p.stdout.decode()
    call_locs = {}
    ind_call_locs = {}
    for l in output.split("\n"):
        if len(l) <= 1:
            continue
        if "QWORD PTR" in l and l.endswith("]"):
            addr = int(l.split(":")[0].strip(), 16)
            lol = "".join(l.split(":")[1].split("[")[1].split("]")[0])
            if '+' in lol:
                reg, off = lol.split("+", 1)
            else:
                reg, off = lol, "0"

            try:
                off = int(off, 0)
            except:
                continue

            ind_call_locs[addr] = (reg, off)
        elif l.split()[-2] == "call":
            call_locs[int(l.split(":")[0].strip(), 16)] = l.split()[-1]
        
    return call_locs, ind_call_locs


call_locs, ind_call_locs = get_calls(p)

def call_reg(p):
    reg = call_locs[p.regs.rip - BASE]
    rax = p.regs[reg]
    print(f"call {hex(p.regs.rip - BASE)} -> {hex(rax - BASE)}")

def ind_call_print(p):
    addr = p.regs.rip - BASE
    reg, off = ind_call_locs[addr]
    reg_val = p.regs[reg]
    mem_target = reg_val + off
    try:
        mem = p.read(mem_target, 8)
        print(f"indcall {hex(addr)} -> {hex(u64(mem) - BASE)}")
    except Exception as e:
        print(e)
        pass

if BASE != 0:
    for c in call_locs:
        p.hook(BASE + c, call_reg)
    
    for c in ind_call_locs:
        p.hook(BASE + c, ind_call_print)

p.run()