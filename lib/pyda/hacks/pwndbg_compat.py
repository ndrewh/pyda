import pyda_core
from types import SimpleNamespace
from functools import partial

from pathlib import Path
from pwnlib.elf.elf import ELF
import sys
import importlib

# import our fake gdb module
from gdb import Value, Type
import pyda

class GDBLibInfo():
    def __init__(self):
        pass

    def sharedlibrary_paths(self):
        mods = pyda_core.list_modules()
        return mods

class GDBLibFile():
    def __init__(self):
        pass

    def get_file(self, path, **kwargs):
        p = Path(path)
        if p.is_file():
            return str(p)

        return None


class GDBLibSymbol():
    def __init__(self):
        pass

    def static_linkage_symbol_address(self, name):
        return None

    def address(self, name):
        return None

    def get(self, addr):
        res = pyda_core.get_module_for_addr(int(addr))
        if res[0] != 'unknown':
            print(f"WARN: Symbol lookup not implemented {hex(addr)} {res}")

        return None

def get_glibc_section_address(section):
    for l in pyda_core.list_modules():
        if "libc.so" in l:
            elf = ELF(l)
            off = elf.get_section_by_name(section).header.sh_addr
            addr = pyda_core.get_base(l) + off
            print(f"glibc addr: {hex(addr)}")
            return addr

    return None

class GDBLibMemory():
    def __init__(self, proc):
        self._p = proc

    def is_readable_address(self, addr):
        try:
            self._p.read(addr, 1)
            return True
        except:
            return False

    def poi(self, t, addr):
        v = self._p.read(addr, t.sizeof)
        # print(f"poi: {hex(addr)} => {v.hex()}")
        return Value(v).cast(t)

    def u32(self, addr):
        return int.from_bytes(self._p.read(addr, 4), pyda.arch.endianness())

    def i32(self, addr):
        return int.from_bytes(self._p.read(addr, 4), pyda.arch.endianness(), signed=True)

    def u64(self, addr):
        return int.from_bytes(self._p.read(addr, 8), pyda.arch.endianness())

    def s64(self, addr):
        return int.from_bytes(self._p.read(addr, 8), pyda.arch.endianness(), signed=True)

    def pvoid(self, addr):
        assert pyda.arch.ptrsize() == 8
        return self.u64(addr)

    def peek(self, addr):
        return chr(self._p.read(addr, 1)[0])

    def read(self, addr, size):
        return self._p.read(addr, size)



class Page():
    def __init__(self, map: pyda.Map) -> None:
        self._map = map

    @property
    def end(self):
        return self._map.end

    @property
    def start(self):
        return self._map.start

    def __contains__(self, addr):
        return self._map.start <= addr < self._map.end

    @property
    def objfile(self):
        return self._map.path

    @property
    def execute(self):
        return self._map.executable

    @property
    def rw(self):
        return self._map.readable and self._map.writable

    @property
    def rwx(self):
        return self.rw and self.execute

class GDBLibVMMap():
    def __init__(self, proc):
        pass

    def find(self, addr):
        info = pyda.xinfo(int(addr))
        return Page(info)

    def get(self):
        return []

class GDBLibArch():
    def __init__(self, proc):
        pass

    @property
    def endian(self):
        return pyda.arch.endianness()

    @property
    def ptrsize(self):
        return pyda.arch.ptrsize()

    def __getattr__(self, name):
        print(f"Arch: {name}")
        raise AttributeError(f"Arch: {name}")

def patch_pwndbg(pwndbg, proc):
    patch_gdblib(pwndbg.gdblib, proc)
    patch_glibc(pwndbg.glibc)

    pwndbg.heap.ptmalloc.HeuristicHeap.multithreaded = False

    pwndbg.heap.current = pwndbg.heap.ptmalloc.HeuristicHeap()
    pwndbg.heap.current.is_statically_linked = lambda: False

    pwndbg.heap.current.mp
    # pwndbg.heap.resolve_heap(is_first_run=True)

class GDBLibConfig():
    def __init__(self):
        self._d = {}

    def __getattr__(self, name):
        if name == "_d":
            return super().__getattr__(name)
        elif name in self._d:
            return self._d[name]
        else:
            return 0

    def __setattr__(self, name, value):
        if name == "_d":
            super().__setattr__(name, value)
        else:
            self._d[name] = value

class GDBRegs():
    def __init__(self, proc):
        self._p = proc

    def __getattr__(self, name):
        return self._p.regs[name]

def patch_gdblib(gdblib, proc):
    gdblib.info = GDBLibInfo()
    gdblib.file = GDBLibFile()
    gdblib.symbol = GDBLibSymbol()
    gdblib.config = GDBLibConfig()

    old_mem = gdblib.memory
    gdblib.memory = GDBLibMemory(proc)
    gdblib.memory.string = old_mem.string

    gdblib.vmmap = GDBLibVMMap(proc)
    gdblib.regs = GDBRegs(proc)
    # gdblib.arch = GDBLibArch(proc)

def patch_glibc(glibc):
    glibc.get_data_section_address = partial(get_glibc_section_address, ".data")
    glibc.get_got_section_address = partial(get_glibc_section_address, ".got")
