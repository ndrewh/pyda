
from enum import Enum
import platform

ARCH = Enum("Arch", "X86 X86_64 ARM64")

def arch():
    if platform.machine() in ["arm64", "aarch64"]:
        return ARCH.ARM64
    elif platform.machine() in ["x86_64", "AMD64"]:
        return ARCH.X86_64
    elif platform.machine() in ["i386", "i686"]:
        return ARCH.X86
    else:
        raise f"Unrecognized architecture {platform.machine()}"

def gdb_arch():
    return {
        ARCH.X86: "i386",
        ARCH.X86_64: "i386:x86-64",
        ARCH.ARM64: "arm64",
    }[arch()]

def endianness():
    return "little"

def os():
    return "linux"

def ptrsize():
    return 8
