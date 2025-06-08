# Quick Start

This guide will walk you through creating your first Pyda analysis tool.

## Basic Usage

Pyda tools follow this pattern:

```bash
pyda <script_path> [script_args] -- <bin_path> [bin_args]
```

The `--` separates your script arguments from the target binary arguments.

## Your First Hook

Let's create a simple tool that hooks the `main` function:

```python title="simple_hook.py"
from pyda import *
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64

# Get a handle to the current process
p = process()

# Load ELF information
e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

# Define a hook function
def main_hook(p):
    print(f"Entered main function!")
    print(f"RSP: {hex(p.regs.rsp)}")
    print(f"RIP: {hex(p.regs.rip)}")

# Register the hook at main
p.hook(e.symbols["main"], main_hook)

# Start execution
p.run()
```

Run it with:
```bash
pyda simple_hook.py -- /bin/ls
```

## Memory and Register Access

Pyda provides intuitive access to process memory and registers:

```python title="memory_example.py"
from pyda import *

p = process()

def my_hook(p):
    # Read registers
    rax_value = p.regs.rax
    rsp_value = p.regs.rsp
    
    # Read memory
    stack_data = p.read(p.regs.rsp, 16)  # Read 16 bytes from stack
    
    # Using slice notation
    stack_bytes = p.mem[p.regs.rsp:p.regs.rsp+16]
    single_byte = p.mem[p.regs.rsp]
    
    # Write memory
    p.write(0x1000, b"Hello World")
    
    # Write registers
    p.regs.rax = 0x1337
    
    print(f"RAX: {hex(rax_value)}")
    print(f"Stack: {stack_data.hex()}")

# Hook any address
p.hook(0x401000, my_hook)
p.run()
```

## Syscall Hooks

Monitor and intercept system calls:

```python title="syscall_example.py"
from pyda import *

p = process()

def write_pre_hook(p, syscall_num):
    """Called before write() syscall"""
    fd = p.regs.rdi
    buf_addr = p.regs.rsi
    count = p.regs.rdx
    
    if fd == 1:  # stdout
        data = p.read(buf_addr, min(count, 100))  # Read up to 100 bytes
        print(f"About to write to stdout: {data}")

def write_post_hook(p, syscall_num):
    """Called after write() syscall"""
    bytes_written = p.regs.rax
    print(f"Write returned: {bytes_written}")

# Register syscall hooks
p.syscall_pre(1, write_pre_hook)   # 1 = SYS_write
p.syscall_post(1, write_post_hook)

p.run()
```

## Library Function Tracing

Create an `ltrace`-like tool:

```python title="my_ltrace.py"
from pyda import *
from pwnlib.elf.elf import ELF

p = process()
e = ELF(p.exe_path)
e.address = p.maps[p.exe_path].base

def trace_libc_call(func_name):
    def hook(p):
        print(f"Called {func_name}")
        
        # Print some arguments (adjust based on function)
        if func_name in ["printf", "puts"]:
            try:
                str_addr = p.regs.rdi
                string = p.read(str_addr, 50).split(b'\x00')[0]
                print(f"  arg1: {string}")
            except:
                pass
    
    return hook

# Hook common libc functions
libc_functions = ["printf", "puts", "malloc", "free", "strlen"]
for func in libc_functions:
    if func in e.symbols:
        p.hook(e.symbols[func], trace_libc_call(func))

p.run()
```

## Next Steps

Now that you understand the basics, check out the [`Process`](../api/process.md) documentation to explore other APIs.

## Common Patterns

### Safe memory access

```python
def my_hook(p):
    try:
        data = p.read(p.regs.rsi, 10)
        print(f"Data: {data}")
    except MemoryError as e:
        print(f"Could not read from {hex(p.regs.rsi)}")
```
