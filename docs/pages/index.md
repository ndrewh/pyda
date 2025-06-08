# Pyda Documentation

Pyda lets you write dynamic binary analysis tools using Python.

Pyda combines [DynamoRIO](https://dynamorio.org)-based instrumentation with a CPython interpreter, allowing you to "inject" Python code into any x86/ARM64 Linux process, without going through GDB or ptrace.

## Features

- **Hooks**: Inspect and modify registers and memory at any instruction.
- **Redirect execution**: Hooks can directly modify the program counter; for example, to cause a function to return early or to skip over a tricky branch.
- **Syscall interception**: Syscall pre/post hooks can capture and modify syscall arguments, and optionally skip the syscall altogether.
- **Package support**: Install and use your favorite packages like normal using `pip` (e.g. pwntools).
- **Graceful multithreading**: Writing tools for multithreaded programs is easy: program threads *share* a Python interpreter, so you can use globals to track and aggregate state over several threads.

## What is Pyda?

Pyda is a...

- **In-process, scriptable debugger**: Pyda hooks can be used as GDB-style breakpoints to inspect/modify registers and memory. Several packages (e.g. pwntools) can be used to look up symbols or parse DWARF info.
- **Reverse engineering tool**: Answer questions like "Where do all these indirect jumps go?" in just a few lines of Python.
- **CTF Tool**: We provide a pwntools-style API for I/O (a Pyda `Process` is actually a pwntools `tube`!), and new "blocking" APIs like `p.run_until(pc)` which allow you to interleave execution and I/O.

## Quick Example

```python
from pyda import *
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64

# Get a handle to the current process
p = process()  # See process() function docs

# You can use pwnlib to get information about the target ELF
e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

# Define a hook/breakpoint -- this can be at any instruction
def main_hook(p):
    print(f"at main, rsp={hex(p.regs.rsp)}")
    return_addr = p.read(p.regs.rsp, 8)
    print(f"return address: {hex(u64(return_addr))}")

# Register the hook
p.hook(e.symbols["main"], main_hook)

# Tell Pyda we are ready to go!
p.run()
```

## Getting Started

Ready to start using Pyda? Check out our [installation guide](getting-started/installation.md) and [quick start tutorial](getting-started/quickstart.md).

For detailed API documentation:
- [`process()` function](api/process.md#process-function) - Main entry point for creating Process instances
- [Process API Reference](api/process.md) - Complete API documentation 