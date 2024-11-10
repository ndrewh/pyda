import pyda_core
from pyda_core import MemoryError, ThreadExitError, InvalidStateError, FatalSignalError
from .process import Process, Map
from . import arch
import sys

INIT = False

def process(**kwargs):
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

FatalSignalError.__str__ = lambda self: f"Signal {self.args[0]} on Thread {self.args[1]}\nBacktrace:\n{self.args[2]}"