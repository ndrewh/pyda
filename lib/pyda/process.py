from collections import namedtuple
from dataclasses import dataclass
import ctypes
from .tube import ProcessTube
import pyda_core

class Process(ProcessTube):
    def __init__(self, handle, io=False):
        self._p = handle

        if io:
            fds = self._p.capture_io()
            super().__init__(fds[0], fds[1])
        else:
            super().__init__(None, None)

        self._hooks = {}
        self._syscall_pre_hooks = {}
        self._syscall_post_hooks = {}
        self._registered_syscall_pre_hook = False
        self._registered_syscall_post_hook = False
        self._has_run = False

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

    def hook(self, addr, callback):
        if addr not in self._hooks:
            hook_wrapper = lambda p: self._hook_dispatch(addr)
            self._p.register_hook(addr, hook_wrapper)

            self._hooks[addr] = [callback]
        else:
            self._hooks[addr].append(callback)

    def unhook(self, addr, callback=None):
        self._hooks[addr] = [c for c in self._hooks[addr] if c != callback]

        if callback is None or len(self._hooks[addr]) == 0:
            del self._hooks[addr]
            self._p.unregister_hook(addr)

    def hook_after_call(self, addr, callback):
        def call_hook(p):
            retaddr = int.from_bytes(p.read(p.regs.rsp, 8), "little")
            def after_call_hook(p):
                # print(f"after call to {hex(addr)}")
                callback(p)
                self.unhook(retaddr, after_call_hook)
            self.hook(retaddr, after_call_hook)

        self.hook(addr, call_hook)

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

    def set_thread_entry(self, callback):
        self._p.set_thread_init_hook(lambda p: callback(self))

    def read(self, addr, size):
        return self._p.read(addr, size)

    def write(self, addr, data):
        return self._p.write(addr, data)

    def __getattr__(self, name):
        # TODO: Move these into CPython extension?
        if name == "regs":
            return ProcessRegisters(self._p)
        elif name == "mem":
            return ProcessMemory(self)
        elif name == "maps":
            return ProcessMaps(self._p)
        elif name == "exe_path":
            return self._p.get_main_module()

        raise AttributeError(f"Invalid attribute '{name}'. Did you mean 'regs.{name}'?")

    def __setattr__(self, name, value):
        if not name.startswith("_") and name not in ["timeout", "buffer", "closed"]:
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


