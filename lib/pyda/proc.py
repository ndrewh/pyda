from collections import namedtuple, deque
from dataclasses import dataclass
import ctypes
import ctypes.util
from .tube import ProcessTube
from .compiler import Builder
from .arch import arch, ARCH
import pyda_core
import sys

class Process(ProcessTube):
    """
    Obtain a `Process` via the module-level `process` function.

    Example:
        Obtain a `Process` with `process()`.

        ```python
        from pyda import *
        
        # process() returns a Process instance.
        p = process()

        # p.run() starts the process.
        p.run()
        ```
    
    The Process class provides the primary API for instrumenting and analyzing 
    target processes. It allows you to set hooks, intercept system calls, and 
    manipulate process state during execution.
    
    This class extends `ProcessTube`, providing pwntools-compatible I/O operations
    alongside the dynamic analysis capabilities.
    
    Attributes:
        regs (ProcessRegisters): Interface for reading/writing CPU registers
        mem (ProcessMemory): Interface for reading/writing process memory  
        maps (ProcessMaps): Interface for querying memory mappings
        exe_path (str): Path to the main executable being analyzed
        tid (int): Current thread ID (valid during hook execution)
    
    Example:
        Basic usage pattern:
        
        ```python
        from pyda import *
        
        # Get process handle
        p = process()
        
        # Set up hooks
        def my_hook(p):
            print(f"Hit address, RAX={hex(p.regs.rax)}")
            
        p.hook(0x401000, my_hook)
        
        # Start analysis
        p.run()
        ```
    """

    def __init__(self, handle, io=False):
        """The following options can be passed to `process()`:
        
        Args:
            io (bool): Whether to capture I/O for pwntools compatibility.
                      When True, enables recv/send operations.
        """
        self._p = handle

        if io:
            fds = self._p.capture_io()
            super().__init__(fds[0], fds[1])
        else:
            super().__init__(None, None)

        self._hooks = {}
        self._builder_hooks = {}
        self._syscall_pre_hooks = {}
        self._syscall_post_hooks = {}
        self._registered_syscall_pre_hook = False
        self._registered_syscall_post_hook = False
        self._has_run = False

        self.regs = ProcessRegisters(handle)
        self.mem = ProcessMemory(handle)
        self.maps = ProcessMaps(handle)

        self.exe_path = self._p.get_main_module()

    def _hook_dispatch(self, addr):
        """Internal method to dispatch hooks at a given address."""
        for h in self._hooks[addr]:
            h(self)

    def _syscall_pre_hook_dispatch(self, syscall_num):
        """Internal method to dispatch pre-syscall hooks."""
        if syscall_num in self._syscall_pre_hooks:
            results = []
            for h in self._syscall_pre_hooks[syscall_num]:
                results.append(h(self, syscall_num))

            if False in results and True in results:
                raise RuntimeError("Cannot have mixed return values from syscall pre-hooks")
            elif False in results:
                return False
            elif True in results:
                return True

    def _syscall_post_hook_dispatch(self, syscall_num):
        """Internal method to dispatch post-syscall hooks."""
        if syscall_num in self._syscall_post_hooks:
            for h in self._syscall_post_hooks[syscall_num]:
                h(self, syscall_num)

    def hook(self, addr, callback, priority=False, later=False):
        """Register a hook at the specified address.
        
        Hooks are functions called before executing the instruction at the 
        specified program counter.
        
        Note:
            Multiple hooks can be registered at the
            same address and will be called in registration order (unless 
            priority=True).
        
        Args:
            addr (int): Memory address where the hook should be installed
            callback (callable): Function to call when the hook is hit. 
                               Should accept one argument (the Process instance)
            priority (bool): If True, adds this hook before existing hooks
                           at the same address
            later (bool): If True, registers the hook but doesn't install it
                        until the address is reached for the first time
        
        Example:
            ```python
            def main_hook(p):
                print(f"Entered main at {hex(p.regs.rip)}")
                print(f"Stack pointer: {hex(p.regs.rsp)}")
            
            p.hook(0x401234, main_hook)
            ```
        
        """
        assert addr not in self._builder_hooks
        if addr not in self._hooks:
            hook_wrapper = lambda p: self._hook_dispatch(addr)
            self._p.register_hook(addr, hook_wrapper, 0, later)
            self._hooks[addr] = deque([callback])
        else:
            if priority:
                self._hooks[addr].appendleft(callback)
            else:
                self._hooks[addr].append(callback)

    def unhook(self, addr, callback=None, unregister=True):
        """Remove a hook from the specified address.
        
        Args:
            addr (int): Address where the hook is installed
            callback (callable, optional): Specific callback to remove. 
                                         If None, removes all hooks at the address
            unregister (bool): Whether to unregister the hook from DynamoRIO
                             if no callbacks remain
        """
        # TODO: Maybe replace this with some kind of hook disabling mechanism
        # (perhaps optimize for hook_after_call use)
        self._hooks[addr] = deque([c for c in self._hooks[addr] if c != callback])

        if (callback is None or len(self._hooks[addr]) == 0) and unregister:
            del self._hooks[addr]
            del self._builder_hooks[addr]
            self._p.unregister_hook(addr)

    def builder_hook(self, addr, builder, later=False):
        """Register a low-level builder hook at the specified address.
        
        Builder hooks provide access to DynamoRIO's instruction builder,
        allowing for more advanced instrumentation scenarios.
        
        Args:
            addr (int): Address where the builder hook should be installed
            builder (callable): Function that accepts a Builder instance
            later (bool): If True, registers the hook for later installation
        
        Note:
            Only one builder hook can be registered per address. Builder hooks
            and regular hooks are mutually exclusive at the same address.
        """
        if addr in self._builder_hooks:
            raise RuntimeError("Only one builder hook can be registered per address")
        assert addr not in self._hooks

        self._builder_hooks[addr] = builder
        self._p.register_hook(addr, lambda b: builder(Builder(b)), 1, later)

    def hook_after_call(self, addr, callback):
        """Register a hook that fires when a function call returns.
        
        This is a convenience method that hooks a function entry point and
        automatically sets up a hook at the return address.
        
        Args:
            addr (int): Address of the function to hook
            callback (callable): Function to call when the function returns
                               
        Example:
            ```python
            def after_malloc(p):
                ptr = p.regs.rax  # Return value in RAX
                print(f"malloc returned: {hex(ptr)}")
                
            p.hook_after_call(libc.symbols['malloc'], after_malloc)
            ```
        
        Note:
            This assumes x86-64 calling convention where return addresses
            are stored on the stack.
        """
        def call_hook(p):
            retaddr = int.from_bytes(p.read(p.regs.rsp, 8), "little")
            def after_call_hook(p):
                # print(f"after call to {hex(addr)}")
                callback(p)
                self.unhook(retaddr, after_call_hook, unregister=False)
            self.hook(retaddr, after_call_hook)

        self.hook(addr, call_hook, priority=True)

    def syscall_pre(self, syscall_num, callback):
        """Register a pre-syscall hook for the specified system call.
        
        Pre-syscall hooks are called before the system call is executed,
        allowing inspection and modification of arguments. They can also
        prevent the syscall from executing by returning False.
        
        Args:
            syscall_num (int): System call number to hook (e.g. 1 for write)
            callback (callable): Function to call before the syscall.
                               Should accept (process, syscall_num) arguments.
                               Can return False to skip the syscall.
        
        Example:
            ```python
            def block_write(p, syscall_num):
                if p.regs.rdi == 1:  # stdout
                    print("Blocking write to stdout")
                    p.regs.rax = -1  # Set error return value
                    return False  # Skip the syscall
                    
            p.syscall_pre(1, block_write)  # Hook SYS_write
            ```
        
        Raises:
            RuntimeError: If called after the process has started running
        """
        if self._has_run:
            raise RuntimeError("Cannot add syscall hooks after process has started")

        if not self._registered_syscall_pre_hook:
            self._p.set_syscall_pre_hook(lambda p, syscall_num: self._syscall_pre_hook_dispatch(syscall_num))
            self._registered_syscall_pre_hook = True

        if syscall_num not in self._syscall_pre_hooks:
            self._syscall_pre_hooks[syscall_num] = [callback]
        else:
            self._syscall_pre_hooks[syscall_num].append(callback)

    def syscall_post(self, syscall_num, callback):
        """Register a post-syscall hook for the specified system call.
        
        Post-syscall hooks are called after the system call completes,
        allowing inspection of return values and side effects.
        
        Args:
            syscall_num (int): System call number to hook
            callback (callable): Function to call after the syscall.
                               Should accept (process, syscall_num) arguments.
        
        Example:
            ```python
            def log_write_result(p, syscall_num):
                bytes_written = p.regs.rax
                print(f"write() returned {bytes_written}")
                
            p.syscall_post(1, log_write_result)
            ```
        
        Raises:
            RuntimeError: If called after the process has started running
        """
        if self._has_run:
            raise RuntimeError("Cannot add syscall hooks after process has started")

        if not self._registered_syscall_post_hook:
            self._p.set_syscall_post_hook(lambda p, syscall_num: self._syscall_post_hook_dispatch(syscall_num))
            self._registered_syscall_post_hook = True

        if syscall_num not in self._syscall_post_hooks:
            self._syscall_post_hooks[syscall_num] = [callback]
        else:
            self._syscall_post_hooks[syscall_num].append(callback)
    
    def on_module_load(self, callback):
        """Register a callback for when new modules are loaded.
        
        Args:
            callback (callable): Function to call when a module loads.
                               Should accept appropriate arguments from DynamoRIO.
        """
        self._p.set_module_load_hook(callback)

    def set_thread_entry(self, callback):
        """Register a callback for when new threads are created.
        
        Args:
            callback (callable): Function to call when a new thread starts.
                               Should accept one argument (the Process instance).
        
        Example:
            ```python
            def new_thread(p):
                print(f"New thread created: TID {p.tid}")
                
            p.set_thread_entry(new_thread)
            ```
        """
        self._p.set_thread_init_hook(lambda p: callback(self))

    def read(self, addr, size):
        """Read memory from the target process. Returns bytes.
        
        Args:
            addr (int): Memory address to read from
            size (int): Number of bytes to read
            
        Example:
            ```python
            # Read 16 bytes from the stack
            stack_data = p.read(p.regs.rsp, 16)
            ```
        """
        return self._p.read(addr, size)

    def write(self, addr, data):
        """Write data to the target process memory.
        
        Args:
            addr (int): Memory address to write to
            data (bytes): Data to write
            
        Example:
            ```python
            # Write a string to memory
            p.write(0x401000, b"Hello World\\x00")
            ```
        """
        return self._p.write(addr, data)

    def __getattr__(self, name):
        if self.regs.has_reg(name):
            raise AttributeError(f"Invalid attribute '{name}'. Did you mean 'regs.{name}'?")
        else:
            raise AttributeError(f"Invalid attribute '{name}'")

    def __setattr__(self, name, value):
        if not name.startswith("_") and name not in ["timeout", "buffer", "closed", "regs", "mem", "maps", "exe_path"]:
            raise AttributeError(f"Cannot set attribute '{name}'")

        super().__setattr__(name, value)

    def run(self):
        """Start or resume execution of the target process.
        
        This method begins execution and will run until the process exits
        or encounters a blocking condition (like waiting for I/O).
        
        Example:
            ```python
            p = process()
            p.hook(0x401000, my_hook)
            p.run()  # Start execution
            ```
        """
        self._has_run = True
        self._p.run()

    def run_until(self, addr):
        """Run the process until it reaches the specified address.
        
        Args:
            addr (int): Address to run until
            
        Example:
            ```python
            # Run until we hit main
            p.run_until(0x401234)
            print(f"Stopped at main, RAX={hex(p.regs.rax)}")
            ```
        """
        self._has_run = True
        self._p.run_until_pc(addr)

    @property
    def tid(self):
        """Get the current thread ID (starts from 1).
        
        Note:
            This property is only valid during hook execution or when the 
            process is stopped.
        """
        # This returns the thread id of the currently executing thread
        return pyda_core.get_current_thread_id()

    def run_from_to(self, start, end):
        """Jump to a specific address and run until another address is reached.
        
        Args:
            start (int): Address to jump to
            end (int): Address to run until
            
        Note:
            This cannot be used from within hooks.
        """
        self.regs.rip = start
        self.run_until(end)

    def callable(self, addr):
        """Create a callable that executes instrumented target code.
        
        Returns a function that, when called, will execute the function at the 
        specified address with the given arguments, following standard calling conventions.
        
        Args:
            addr (int): Address of the function to call
            
        Example:
            ```python
            # Create a callable for malloc
            malloc = p.callable(libc.symbols['malloc'])
            
            # Call malloc(100) 
            p.run_until(main_addr)  # Establish stack first
            ptr = malloc(100)
            ```
            
        Note:
            - Cannot be used from within hooks
            - Requires the process to have a valid stack
            - Currently supports up to 6 arguments (x86-64 limitation)
        """
        def call(*args):
            if not self._has_run:
                raise RuntimeError("Cannot use callable before first process break (no stack!). Try p.run_until(e.symbols['main']) first")

            self._p.push_state()

            ## BEGIN ARCH-SPECIFIC SETUP
            orig_pc = self.regs.pc

            if arch() in [ARCH.X86_64, ARCH.X86]:
                # Push orig_pc as the return address
                self.regs.rsp &= ~0xf
                self.regs.rsp -= 8
                self.write(self.regs.rsp, orig_pc.to_bytes(8, "little"))

                target_sp = self.regs.rsp + 8
            elif arch() == ARCH.ARM64:
                # Emulate a blr: just update lr
                self.regs.x30 = orig_pc
                # (note that old LR was saved in self._p.push_state())

                target_sp = self.regs.sp

            set_regs_for_call_linux(self, args)

            print(f"current_pc={hex(self.regs.pc)} target={hex(addr)}")
            self.regs.pc = addr

            # This is a bit hacky, but basically
            # we don't actually know that orig_pc is outside
            # of the function, we just know it's a reasonably
            # safe address. You'll get unexpectedly bad perf
            # if your original pc is garbage

            count = 0
            try:
                while True:
                    self.run_until(orig_pc)
                    count += 1

                    if self.regs.sp == target_sp:
                        break
                ## END ARCH-SPECIFIC SETUP

            finally:
                if count > 1:
                    self.warning(f"WARN: Callable should be used from a safe pc not within the callee.")

                self._p.pop_state()

        return call

    def backtrace(self):
        """Get a string representation of the current call stack.
        
        Example:
            ```python
            def crash_hook(p):
                print("Crash detected!")
                print("Backtrace:")
                print(p.backtrace())
            ```
        """
        return backtrace_to_str(self._p.backtrace())

    def backtrace_cpp(self, short=False):
        """Get a C++ demangled backtrace of the current call stack.
        
        Args:
            short (bool): If True, truncate long symbol names
        """
        return backtrace_to_str(self._p.backtrace(), demangle=True, short=short)

def find_any_library(*choices: str) -> str:
    for choice in choices:
        lib = ctypes.util.find_library(choice)
        if lib is not None:
            return lib
    raise LibraryNotFound('Cannot find any of libraries: {}'.format(choices))

try:
    libcxx = find_any_library("stdc++", "c++")
    libcxx = ctypes.CDLL(libcxx)  # On Linux
    cxa_demangle = getattr(libcxx, '__cxa_demangle')
    cxa_demangle.restype = ctypes.c_void_p
except LibraryNotFound:
    libcxx = None

def cxx_demangle(s):
    mangled_name_p = ctypes.c_char_p(s.encode('utf-8'))
    status = ctypes.c_int()
    retval = cxa_demangle(mangled_name_p, None, None, ctypes.pointer(status))

    res = None
    if status.value == 0:
        try:
            res = ctypes.c_char_p(retval).value.decode('utf-8')
        finally:
            pyda_core.free(retval)

    return res

def backtrace_to_str(bt, demangle=False, short=False):
    if demangle:
        if "cxxfilt" not in sys.modules:
            import cxxfilt

        cxxfilt = sys.modules["cxxfilt"]

    s = ""
    for f in bt:
        if demangle and f[3].startswith("_Z"):
            sym = cxx_demangle(f[3])
            if short and len(sym) > 100:
                sym = sym[:50] + "..." + sym[-50:]

            s += f"[{f[1]}+{hex(f[2])}] {sym}\n"
        elif f[2] != 0:
            s += f"[{f[1]}+{hex(f[2])}] {f[3]}\n"
        else:
            s += f"[ip={hex(f[0])}]\n"

    return s

def set_regs_for_call_linux(p, args):
    if len(args) > 6:
        raise NotImplementedError(">6 args not supported yet")

    if arch() == ARCH.X86_64:
        ARGS = [
            pyda_core.REG_RDI,
            pyda_core.REG_RSI,
            pyda_core.REG_RDX,
            pyda_core.REG_RCX,
            pyda_core.REG_R8,
            pyda_core.REG_R9
        ]
    elif arch() == ARCH.ARM64:
        ARGS = [
            pyda_core.REG_X0,
            pyda_core.REG_X1,
            pyda_core.REG_X2,
            pyda_core.REG_X3,
            pyda_core.REG_X4,
            pyda_core.REG_X5
        ]
    else:
        raise NotImplementedError(f"set_regs_for_call_linux not implemented for {arch()}")

    for (reg_id, val) in zip(ARGS, args):
        if type(val) is int:
            p._p.set_register(reg_id, val)
        elif type(val) is bytes:
            ptr = ctypes.cast(ctypes.c_char_p(val), ctypes.c_void_p).value
            p._p.set_register(reg_id, ptr)
        else:
            raise ValueError(f"Invalid argument type {type(val)}")

class ProcessRegisters():
    """Interface for reading and writing CPU registers.
    
    Provides convenient access to CPU registers using both attribute and 
    dictionary-style syntax.
    
    Example:
        ```python
        # Reading registers
        rax_val = p.regs.rax
        rsp_val = p.regs['rsp']
        
        # Writing registers  
        p.regs.rax = 0x1337
        p.regs['rbx'] = 0x2000
        ```
    """
    
    def __init__(self, p):
        self._p = p

    def __getitem__(self, name):
        val = None
        reg_id = getattr(pyda_core, "REG_"+name.upper(), None)
        if reg_id:
            val = self._p.get_register(reg_id)

        if val is not None:
            return val

        raise AttributeError(f"Invalid register name '{name}'")

    def __setitem__(self, name, value):
        reg_id = getattr(pyda_core, "REG_"+name.upper(), None)
        if reg_id:
            self._p.set_register(reg_id, value)
        else:
            raise AttributeError(f"Invalid register name '{name}'")

    def __getattr__(self, name):
        return self[name]

    def __setattr__(self, name, value):
        if name != "_p":
            self[name] = value
        else:
            super().__setattr__(name, value)

    def has_reg(self, name):
        """Check if a register name is valid."""
        return hasattr(pyda_core, "REG_"+name.upper())

class ProcessMemory():
    """Interface for reading and writing process memory.
    
    Provides convenient slice-based access to target process memory.
    
    Example:
        ```python
        # Read single byte
        byte_val = p.mem[0x401000]
        
        # Read range of bytes
        data = p.mem[0x401000:0x401010]  # 16 bytes
        
        # Write data
        p.mem[0x401000:0x401004] = b"\\x41\\x41\\x41\\x41"
        ```
    """
    
    def __init__(self, p):
        self._p = p

    def __getitem__(self, key):
        if type(key) is slice:
            start = key.start
            stop = key.stop
            step = key.step
            if step is not None and step != 1:
                raise ValueError("ProcessMemory: Step must be 1")

            if stop is not None:
                return self._p.read(start, stop - start)
            else:
                return self._p.read(start, 1)[0]

        return self._p.read(key, 1)[0]

class ProcessMaps():
    """Interface for querying process memory mappings.
    
    Example:
        ```python
        # Get base address of main executable
        main_base = p.maps[p.exe_path].base
        
        # Get libc base
        libc_base = p.maps["libc.so.6"].base
        ```
    """
    
    def __init__(self, p):
        self._p = p

    def __getitem__(self, key):
        return Map(vaddr=pyda_core.get_base(key), size=0, path=key, perms=None)


@dataclass
class Map:
    """Represents a memory mapping in the target process."""
    vaddr: int
    size: int
    path: str
    perms: int

    @property
    def base(self):
        """Base address of this mapping."""
        return self.vaddr

    @property
    def start(self):
        """Start address (same as base)."""
        return self.vaddr

    @property
    def end(self):
        """End address of this mapping."""
        return self.base + self.size

    @property
    def executable(self):
        """True if mapping has execute permissions."""
        return self.perms & 1

    @property
    def writable(self):
        """True if mapping has write permissions."""
        return self.perms & 2

    @property
    def readable(self):
        """True if mapping has read permissions."""
        return self.perms & 4


