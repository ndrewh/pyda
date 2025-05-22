Pyda
====

Pyda lets you write dynamic binary analysis tools using Python.

Pyda combines [Dynamorio](https://dynamorio.org)-based instrumentation with a CPython interpreter, allowing you to
"inject" Python code into any x86/ARM64 Linux process, without
going through GDB or ptrace.

Features:
- **Hooks**: Inspect and modify registers
and memory at any instruction.
- **Redirect execution**: Hooks can directly modify the program
counter; for example, to cause a function to return early or to
skip over a tricky branch.
- **Syscall interception**: Syscall pre/post hooks can capture and modify syscall
arguments, and optionally skip the syscall altogether.
- **Package support**: Install and use your favorite packages like
normal using `pip` (e.g. pwntools).
- **Graceful multithreading**: Writing tools for multithreaded programs is easy:
program threads *share* a Python interpreter[*](#multithreading), so you can use globals to
track and aggregate state over several threads (see: [`p.tid`](#api)).


Pyda is a...
- **In-process, scriptable debugger**: Pyda hooks can be used as GDB-style breakpoints
to inspect/modify registers and memory. Several packages (e.g. pwntools) can be used
to look up symbols or parse DWARF info.
- **Reverse engineering tool**: Answer questions like "Where do all these indirect jumps go?" in just a few lines of Python.
- **CTF Tool**: We provide a pwntools-style API for I/O (a Pyda `Process` is actually a pwntools `tube`!), and
new "blocking" APIs like `p.run_until(pc)` which allow you to interleave execution and I/O.

#### Quickstart

```sh
docker run -it ghcr.io/ndrewh/pyda pyda examples/ltrace.py -- ls -al
```


## Example
> [!WARNING]
> This API is not stable and may change. Please provide
> feedback on the API by filing an issue.

```py
from pyda import *
from pwnlib.elf.elf import ELF
from pwnlib.util.packing import u64

# Get a handle to the current process
p = process()

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

```
$ pyda examples/simple.py -- ./challenge 
at main, rsp=0x7fff1303f078
return address: 0x7f3c50420d90
```


### More examples
See [examples/](examples/) for additional examples.

- [`ltrace.py`](examples/ltrace.py): Hook all calls to library functions, and print out their arguments
- [`strace.py`](examples/strace.py): Hook all syscalls and print out their arguments
- [`cmplog.py`](examples/cmplog.py): Hook all `cmp` instructions and print out their arguments
- [`resolve_indirect_calls.py`](examples/resolve_indirect_calls.py): dump a list of indirect calls with `objdump`, and then
print out the targets during execution


## Limitations
- Currently Linux/macOS only (please contribute Windows support!)
- Currently X86_64/ARM64 only (please contribute support for other architectures)
- All of the limitations of Dynamorio apply. (The program must be reasonably well behaved. You should assume a sufficiently motivated program can detect whether it is running under Dynamorio.)
- Some state may be shared with the target process; while Dynamorio
attempts to isolate our libc (and other libraries) from the target, OS structures (e.g. fds)
are shared.

## Getting started

### Install

Suggested use is via Docker.

Pull the latest release:
```sh
docker pull ghcr.io/ndrewh/pyda
```

Or build it yourself:
```sh
docker build -t pyda .
```

(The Pyda image is currently based on `ubuntu:22.04` and we leave the default entrypoint as `/bin/bash`)

### Experimental pip install (macOS and Linux)

> [!WARNING]
> macOS support is extremely experimental and may not work.

Installation with pip may take ~1-2 minutes to complete, as it builds everything from source.
**Pyda currently only supports CPython 3.10.**

```sh
pip install pyda-dbi
```

### Usage
```sh
pyda <script_path> [script_args] -- <bin_path> [bin_args]
```

"Hello World" example: `ltrace` over `/bin/ls`
```sh
pyda examples/ltrace.py -- ls
```
### API

You can view all of the available APIs in [process.py](https://github.com/ndrewh/pyda/blob/master/lib/pyda/process.py), but in summary:

Read/Modify Memory and Registers:

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
```

Hooks:

```py
# Hooks (functions called before executing the instruction at the specified PC)
p.hook(0x100000, lambda p: print(f"rsp={hex(p.regs.rsp)}"))

# New thread events: called when a new thread starts (just before entrypoint)
p.set_thread_entry(lambda p: print(f"tid {p.tid} started")) # Called when a new thread is spawned

# Syscall hooks: called for a specific syscall (specified by the first arg)
# as a pre (before syscall) or post (after syscall) hook.
#
# Pre-syscall hooks can optionally return False to skip the syscall.
# In this case, you are responsible for setting the return value
# (e.g. with p.regs.rax = 0). Returning any value other than False (or not
# returning anything at all) will still run the syscall.
p.syscall_pre(1, lambda p, syscall_num: print(f"write about to be called with {p.regs.rdx} bytes"))
p.syscall_post(1, lambda p, syscall_num: print(f"write called with {p.regs.rdx} bytes"))
```

Debugger-style "blocking" APIs:
```py
# Resumes the process until completion
p.run()

# Resumes the process until `pc` is reached
p.run_until(pc)

# pwntools tube APIs are overloaded:
# recvuntil(x) resumes the process until it reaches a "write" syscall
# that writes matching data
p.recvuntil(bstr)
```

Misc
```py
# Get process base
p.maps["libc.so.6"].base # (int)

# Get current thread id (valid in hooks and thread entrypoint)
p.tid # (int), starts from 1
```

### FAQ

**Why should I use this over GDB or other ptrace-based debuggers?** 

GDB breakpoints incur substantial overhead due to signal handling in the kernel and in
the tracer process.  This introduces an insurmountable
performance challenge for high-frequency breakpoints.
For multithreaded programs, this problem is compounded by
["group-stop"](https://man7.org/linux/man-pages/man2/ptrace.2.html), which will
stop *all* threads when *any* thread receives a stop signal.

Unlike GDB, Pyda hooks are executed directly in the target process itself (without the overhead of signals
or a kernel context switch). As a result, Pyda hooks typically run faster.

**Why should I use this over Frida or other dynamic instrumentation tools?**

These tools are quite similar to Pyda, with mostly ergonomic differences: Pyda tools
are written in Python using a relatively minimal set of [APIs](#api). Pyda relies on the existing Python ecosystem for many features (e.g. ELF parsing).
As a result, Pyda tools are typically shorter and easier to write than equivalent Frida scripts.

However, Pyda is **not** (currently) an adequate replacement for full-fledged dynamic instrumentation
frameworks. We do not provide a fine-grained instrumentation API (e.g.
you cannot insert specific instructions), relying instead on hooks
as the primary unit of instrumentation.

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

Pyda runs as a [Dynamorio](https://dynamorio.org) tool: `pyda` is just a `drrun` wrapper that runs the application under dynamorio with our tool loaded. Technically,
Pyda is "just" a shared object that links against `libPython`---both of which get loaded into the target process by Dynamorio. However, Dynamorio is designed to support
_targets_ which load the same libraries as required by _tools_ (i.e., by including it's own [private loader](https://dynamorio.org/using.html) for tools).
As you might imagine, it gets a bit messy to run CPython under a nonstandard loader,
and we had to include nontrivial patches for both Dynamorio and CPython to make it all work.
There were also issues with the ["Client Transparency"](https://dynamorio.org/transparency.html)
aspects of Dynamorio: in particular, our tool's threads reside in a different process group than the target itself
(despite residing in the same memory space). This causes problems
with certain concurrency primatives (e.g. `sem_init`/`sem_wait`) that rely on threads being in the same process group.

Dynamorio handles all the nasty low-level details: inserting instrumentation, machine state trasitions to/from hooks, etc. Pyda provides
a CPython extension for registering hooks and proxies machine state modifications to Dynamorio. Pyda itself ends up handling
a lot of edge cases (think: hooks which throw exceptions, hooks which remove themselves, redirect execution, etc.) and nasty error states, especially surrounding thread creation and cleanup.

### Multithreading

While in theory `ptrace` allows threads to be started and stopped independently, most interactive debuggers like GDB automatically suspend *all* threads
when *any* thread reaches a breakpoint (for more infomation, see GDB's `scheduler-locking` option and and the ptrace ["group-stop" documentation](https://man7.org/linux/man-pages/man2/ptrace.2.html)).

Like GDB breakpoints, Pyda hooks are global to all threads. But unlike GDB, hook execution does not interrupt other threads (except as described below).

Programs running under Pyda get a single CPython interpreter, so all threads share the same state (globals). When a hook
is called by a thread, the thread will first acquire the GIL. This effectively serves as a global lock over all hooks, but we may try to eliminate this in a future release.

We maintain a thread-specific
data structure using Dynamorio's TLS mechanism, which allows us to track thread creation/destruction
and report thread-specific information (e.g. `p.tid`) in hooks.

## Contributing

Issues and pull requests are welcome. If reporting an issue with a particular target, please attach the binary.

