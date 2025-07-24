### Read/Modify Memory and Registers

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

### Hooks

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

### Debugger-style "blocking" APIs:

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

### Misc

```py
# Get process base
p.maps["libc.so.6"].base # (int)

# Get current thread id (valid in hooks and thread entrypoint)
p.tid # (int), starts from 1
```
