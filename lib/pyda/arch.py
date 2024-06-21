
from enum import Enum

ARCH = Enum("Arch", "X86 X64")


def arch():
    # todo: arch detection from dynamorio
    return ARCH.X64

def gdb_arch():
    return {
        ARCH.X86: "i386",
        ARCH.X64: "i386:x86-64",
    }[arch()]

def endianness():
    return "little"

def os():
    return "linux"

def ptrsize():
    return 8
