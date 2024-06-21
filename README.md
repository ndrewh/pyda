Pyda
====

Pyda lets you write simple *dynamic* binary analysis tools using Python.

Pyda combines [Dynamorio](https://dynamorio.org)-based instrumentation with a CPython interpreter, allowing you to ***write hooks
in Python*** that can manipulate memory/registers in the target, ***without going through ptrace***. The interpreter runs in the same
process as the target, resulting in a faster and more pleasant development experience vs. GDB.

It is intended to fufill many of the same use-cases as debuggers (e.g. GDB/Pwndbg),
or complex dynamic instrumentation frameworks (Frida, Dynamorio, DynInst, PIN, etc.).
It was designed with CTF challenges (pwn/rev) in mind.

#### Quickstart

```sh
docker run -it ghcr.io/ndrewh/pyda
pyda <script_name> -- <target> <target_args>
```


Example
-----
> [!WARNING]
> This API is not stable and will likely change. Please provide
> feedback on the API by filing an issue.

```py
from pyda import *
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64

# Get a handle to the current process
p = process()

# Get the binary base address
e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

# Define a hook/breakpoint -- this can be at any instruction
def main_hook(p):
    print(f"at main, rsp={hex(p.regs.rsp)}")
    return_addr = p.read(p.regs.rsp, 8)
    print(f"return address: {hex(u64(return_addr))}")

# Register the hook, and run the binary
p.hook(e.symbols["main"], main_hook)
p.run()
```

```
$ pyda examples/simple.py -- ./challenge 
You are running Pyda v0.0.1
at main, rsp=0x7fff1303f078
return address: 0x7f3c50420d90
```

See [examples/](examples/) for additional examples.

Current features:
-----
- Hooks (aka "breakpoints" if you prefer) at arbitrary instructions
- Read and write memory
- Read and modify registers

## Limitations
- Currently broken on multithreaded programs, JITs, non-linux, etc.
- Currently X86_64 only (please contribute ARM64 support!)
- All of the limitations of Dynamorio apply. The program must be reasonably well behaved.
- Some state may be shared with the target process; while Dynamorio
attempts to isolate our libc from the target, OS structures (e.g. fds)
are shared.

## Usage

### Install

Suggested use is via Docker:
```sh
docker build -t pyda .
docker run -it pyda
```

Usage:
```sh
pyda <script_path> [script_args] -- <bin_path> [bin_args]
```

"Hello World" example: Dump a list of indirect call targets in a binary
```sh
pyda examples/resolve_indirect_calls.py -- /usr/bin/ls
```

### Examples

- [`resolve_indirect_calls.py`](examples/resolve_indirect_calls.py): dump a list of indirect calls with `objdump`, and then
print out the targets during execution

### API

You can view all of the available APIs in [process.py](https://github.com/ndrewh/dynamorio-tool/blob/master/lib/pyda/process.py), but in summary:

```py
# Read memory
p.read(0x100000, 8) # 8 bytes (bytes)
p.mem[0x100000] # 1 byte (int)
p.mem[0x100000:0x100008] # 8 bytes (bytes)

# Write memory
p.write(0x100000, b"\x00" * 8)
p.mem[0x100000:0x100008] = b"\x00" * 8

# Read registers
p.regs.rax # (int)

# Write registers
p.regs.rax = 0x1337133713371337

# Get process base
p.maps["libc.so.6"] # (int)

# Register hooks
p.hook(0x100000, lambda p: print(f"rsp={hex(p.regs.rsp)}"))
```

### FAQ

**Why should I use this over { GDB, Frida, Pwndbg }?** 

If you like
scripting in these tools and are happy with their performance, then
you probably don't need this tool.

**Can I use `LD_LIBRARY_PATH` on the target?**

Generally, yes. Just
run `pyda` with `LD_LIBRARY_PATH` -- the target uses a normal loader.

**Can I run this tool on itself?**

Probably not. But you ***can*** run the Python interpreter under it.
```
$ pyda <script> -- python3
Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 
```

**Can my scripts parse arguments?**

Yes. Script arguments can be passed before
the `--` when running `pyda`. For example:
```sh
pyda script.py --option1 --option2 -- ls
```

Your script can parse these options like normal
with the `argparse` module.

## How it works

Pyda runs as a [Dynamorio](https://dynamorio.org) tool: `pyda` is just a `drrun` wrapper. We include compatibility patches for both Dynamorio and CPython. Dynamorio handles all the nasty details: inserting instrumentation, machine state trasitions to/from hooks, etc.

Dynamorio normally supports a variety of custom "tools" or "clients"
which can insert instrumentation into generic targets using a variety
of APIs. Our tool "simply" links against libpython, allowing us to run
a python interpreter alongside the original program. We run the python
interpreter in a separate thread, and synchronize this thread
with target execution.

For hooks, we use the built-in Dynamorio "clean call" mechanism.

## Contributing

Issues and pull requests are welcome. If reporting an issue with a particular target, please attach the binary.

