import pyda_core
from pyda_core import MemoryError, ThreadExitError, InvalidStateError, FatalSignalError
from .proc import Process, Map, backtrace_to_str
from . import arch, tube, compiler
import sys, os

INIT = False

def process(**kwargs):
    """Obtain the current `Process` instance.
    
    Args:
        **kwargs: Additional arguments passed to Process constructor.
                 Common options include:
                 - io (bool): Enable I/O capture for pwntools compatibility
        
    Example:
        ```python
        from pyda import *
        
        # Basic usage
        p = process()
        
        # With I/O capture enabled
        p = process(io=True)
        ```
        
    Note:
        This function must be called from within the Pyda environment (i.e., when
        running a script via the `pyda` or `pyda-attach` commands).
    """
    global INIT

    # todo: remove the bogus argument
    proc = Process(pyda_core.process(""), **kwargs)

    if not INIT:
        # by this point, hacks/ is in pythonpath
        import pwndbg_compat

        INIT = True
        if "pwndbg" in sys.modules:
            pwndbg_compat.patch_pwndbg(sys.modules["pwndbg"], proc)

    return proc

def xinfo(addr):
    # print(f"find page: {hex(int(addr))}")
    res = pyda_core.get_module_for_addr(addr)
    # print(f"res: {res}")
    if res is None:
        return None
    path, start, end, perms = res
    return Map(path=path, vaddr=start, size=end - start, perms=perms)

FatalSignalError.__str__ = lambda self: f"Signal {self.args[0]} on Thread {self.args[1]}\nBacktrace:\n{backtrace_to_str(self.args[2])}"

def exit(*args, **kwargs):
    raise RuntimeError("exit")

os._exit = exit
sys.exit = exit
