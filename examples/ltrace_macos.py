from pyda import *
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64
from collections import defaultdict
import string
import sys
import subprocess, re, time

def parse_text_stubs(binary_path: str):
    stubs = {}

    cmd = ["otool", "-Iv", binary_path]
    vaddr_cmd = f"otool -l {binary_path} | grep -A 4 '__TEXT'"
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        result2 = subprocess.run(vaddr_cmd, capture_output=True, text=True, check=True, shell=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error running otool: {e}")

    output = result.stdout
    stubs_section = False
    symbols = []

    base_addr = None
    for l in result2.stdout.split("\n"):
        parts = l.split()
        if len(parts) >= 2 and parts[0] == "vmaddr":
            base_addr = int(parts[1], 16)
            break

    for line in output.split('\n'):
        if "__TEXT,__stubs" in line:
            stubs_section = True
            continue
        elif "__DATA" in line:  # Stop when we hit the DATA section
            break

        if stubs_section and line.strip():
            # Skip header line
            if "address" in line:
                continue

            # Parse symbol entries
            match = re.match(r"(0x[0-9a-fA-F]+)\s+(\d+)\s+(.+)", line)
            if match:
                address = int(match.group(1), 16) - base_addr
                index = int(match.group(2))
                name = match.group(3)
                stubs[address] = name

    return stubs


p = process()

base = p.maps[p.exe_path].base
plt_map = { addr + base: name for (addr, name) in parse_text_stubs(p.exe_path).items() }

print({ hex(x): y for (x, y) in plt_map.items() })

def guess_arg(x):
    printable_chars = bytes(string.printable, 'ascii')
    return hex(x)

    # Is pointer?
    if x > 0x100000000:
        try:
            data = p.read(x, 0x20)
            if all([c in printable_chars for c in data[:4]]):
                return str(data[:data.index(0)])
        except:
            pass

    return hex(x)

counts = defaultdict(int)
def lib_hook(p):
    name = plt_map[p.regs.pc]
    print(f"{name}[tid={p.tid}](" + ", ".join([
        f"rdi={guess_arg(p.regs.arg1)}",
        f"rsi={guess_arg(p.regs.arg2)}",
        f"rdx={guess_arg(p.regs.arg3)}",
        f"rcx={guess_arg(p.regs.arg4)}",
    ]) + ")", flush=True)
    counts[name] += 1

for x in plt_map:
    p.hook(x, lib_hook)

p.run()
print(counts)
