# Inline instrumentation

Some hooks can be made into "builder hooks". Builder hooks only run when needed to "build" instrumentation,
and do not actually run for every execution like regular hooks.

Builder hooks must be branchless, and all state modifications must go through `b.load` and `b.store`, or `b.regs.xxx`.

Since builder hooks are not called for every execution, modifying Python globals in your hook
is nonsensical. The `Global` class can be used to wrap any ctypes integral or array type to provide
access to global state.

These hooks have much better performance than normal hooks, since they do not incur
the python calling overhead. Instead, your instrumentation is "compiled" to run inline with the
program's code.

Currently, we do not provide a "select" operation that would allow you to emulate `if` statements. Creative
instrumenters can probably make do without it, but hopefully it will be added eventually.

## Example: Modify a register value

```python3
def lib_hook(p):
    # This function will only be called ~once, even if the instrumentation point
    # is reached thousands of times! Still, the register will be updated every time.
    p.regs.rdi += 1337

p.builder_hook(e.address + 0x1056, lib_hook)
p.run()
```


## Example: Count the number of times a particular pc is reached

```python3
counter = Global(ctypes.c_long(0))

def lib_hook(b):
    counter.val += 1

p.builder_hook(e.address + 0x1056, lib_hook)
p.run()

print(counter.val)
```

## Example: Record register values in a circular buffer

```python3
counter = Global(ctypes.c_long(0))
buf = Global((ctypes.c_long * 0x1000)())

def lib_hook(b):
    counter.val += 1
    buf[counter % 4] = 5

p.builder_hook(e.address + 0x1056, lib_hook)
p.run()

print(buf.val)
```

## Example: Insert arbitrary assembly code

```python3
from pwn import asm

code = asm("nop", arch="amd64")

def lib_hook(b):
    b.raw(code)

p.builder_hook(e.address + 0x1056, lib_hook)
p.run()
```


