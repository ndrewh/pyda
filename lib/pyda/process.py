from collections import namedtuple, deque
from dataclasses import dataclass
import ctypes
import ctypes.util
from .tube import ProcessTube
from .compiler import Builder
import pyda_core
import sys

class Process(ProcessTube):
    def __init__(self, handle, io=False):
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
        for h in self._hooks[addr]:
            h(self)

    def _syscall_pre_hook_dispatch(self, syscall_num):
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
        if syscall_num in self._syscall_post_hooks:
            for h in self._syscall_post_hooks[syscall_num]:
                h(self, syscall_num)

    def hook(self, addr, callback, priority=False, later=False):
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
        # TODO: Maybe replace this with some kind of hook disabling mechanism
        # (perhaps optimize for hook_after_call use)
        self._hooks[addr] = deque([c for c in self._hooks[addr] if c != callback])

        if (callback is None or len(self._hooks[addr]) == 0) and unregister:
            del self._hooks[addr]
            del self._builder_hooks[addr]
            self._p.unregister_hook(addr)

    def builder_hook(self, addr, builder, later=False):
        if addr in self._builder_hooks:
            raise RuntimeError("Only one builder hook can be registered per address")
        assert addr not in self._hooks

        self._builder_hooks[addr] = builder
        self._p.register_hook(addr, lambda b: builder(Builder(b)), 1, later)

    def hook_after_call(self, addr, callback):
        def call_hook(p):
            retaddr = int.from_bytes(p.read(p.regs.rsp, 8), "little")
            def after_call_hook(p):
                # print(f"after call to {hex(addr)}")
                callback(p)
                self.unhook(retaddr, after_call_hook, unregister=False)
            self.hook(retaddr, after_call_hook)

        self.hook(addr, call_hook, priority=True)

    def syscall_pre(self, syscall_num, callback):
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
        self._p.set_module_load_hook(callback)

    def set_thread_entry(self, callback):
        self._p.set_thread_init_hook(lambda p: callback(self))

    def read(self, addr, size):
        return self._p.read(addr, size)

    def write(self, addr, data):
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
        self._has_run = True
        self._p.run()

    def run_until(self, addr):
        self._has_run = True
        self._p.run_until_pc(addr)

    @property
    def tid(self):
        # This returns the thread id of the currently executing thread
        return pyda_core.get_current_thread_id()

    # Jumps to "start" and runs until "end" is reached
    # NOTE: This cannot be used from hooks
    def run_from_to(self, start, end):
        self.regs.rip = start
        self.run_until(end)

    # Returns a function that calls into (instrumented) target code
    # NOTE: This cannot be used from hooks
    def callable(self, addr):
        def call(*args):
            if not self._has_run:
                raise RuntimeError("Cannot use callable before first process break (no stack!). Try p.run_until(e.symbols['main']) first")

            self._p.push_state()

            ## BEGIN ARCH-SPECIFIC SETUP
            orig_rip = self.regs.rip

            # Push orig_rip as the return address
            self.regs.rsp &= ~0xf
            self.regs.rsp -= 8
            self.write(self.regs.rsp, orig_rip.to_bytes(8, "little"))

            set_regs_for_call_linux_x86(self, args)
            target_rsp = self.regs.rsp + 8

            self.regs.rip = addr

            # This is a bit hacky, but basically
            # we don't actually know that orig_rip is outside
            # of the function, we just know it's a reasonably
            # safe address. You'll get unexpectedly bad perf
            # if your original RIP is garbage

            count = 0
            try:
                while self.regs.rsp != target_rsp:
                    self.run_until(orig_rip)
                    count += 1
                ## END ARCH-SPECIFIC SETUP

            finally:
                if count > 1:
                    self.warning(f"WARN: Callable should be used from a safe RIP not within the callee.")

                self._p.pop_state()

        return call

    def backtrace(self):
        return backtrace_to_str(self._p.backtrace())

    def backtrace_cpp(self, short=False):
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

def set_regs_for_call_linux_x86(p, args):
    if len(args) > 6:
        raise NotImplementedError(">6 args not supported yet")

    ARGS = [
        pyda_core.REG_RDI,
        pyda_core.REG_RSI,
        pyda_core.REG_RDX,
        pyda_core.REG_RCX,
        pyda_core.REG_R8,
        pyda_core.REG_R9
    ]
    for (reg_id, val) in zip(ARGS, args):
        if type(val) is int:
            p._p.set_register(reg_id, val)
        elif type(val) is bytes:
            ptr = ctypes.cast(ctypes.c_char_p(val), ctypes.c_void_p).value
            p._p.set_register(reg_id, ptr)
        else:
            raise ValueError(f"Invalid argument type {type(val)}")

class ProcessRegisters():
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
        return hasattr(pyda_core, "REG_"+name.upper())

class ProcessMemory():
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
    def __init__(self, p):
        self._p = p

    def __getitem__(self, key):
        return Map(vaddr=pyda_core.get_base(key), size=0, path=key, perms=None)


@dataclass
class Map:
    vaddr: int
    size: int
    path: str
    perms: int

    @property
    def base(self):
        return self.vaddr

    @property
    def start(self):
        return self.vaddr

    @property
    def end(self):
        return self.base + self.size

    @property
    def executable(self):
        return self.perms & 1

    @property
    def writable(self):
        return self.perms & 2

    @property
    def readable(self):
        return self.perms & 4


