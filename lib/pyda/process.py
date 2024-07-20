from collections import namedtuple
from dataclasses import dataclass
import pyda_core

class Process():
    def __init__(self, handle, prevent_close_stdio=True):
        self._p = handle
        self._hooks = {}
        self._syscall_pre_hooks = {}
        self._syscall_post_hooks = {}
        self._registered_syscall_pre_hook = False
        self._registered_syscall_post_hook = False
        self._has_run = False

        def prevent_close(p, num):
            if p.regs.rdi in [0, 1, 2]:
                p.regs.rax = 0
                return False # pre-hooks that return False will prevent the syscall from executing
            
            return None

        if prevent_close_stdio:
            self.syscall_pre(3, prevent_close)
    
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
                print(f"after call to {hex(addr)}")
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
        if name in "regs":
            return ProcessRegisters(self._p)
        elif name == "mem":
            return ProcessMemory(self)
        elif name == "maps":
            return ProcessMaps(self._p)
        elif name == "exe_path":
            return self._p.get_main_module()

        raise AttributeError(f"Invalid attribute '{name}'. Did you mean 'regs.{name}'?")
    
    def run(self):
        self._has_run = True
        self._p.run()
    
    @property
    def tid(self):
        # This returns the thread id of the currently executing thread
        return pyda_core.get_current_thread_id()
    

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
    

