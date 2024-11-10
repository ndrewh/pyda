from types import SimpleNamespace
import pyda
import pyda_core

# This is a compatibility layer for pwndbg

PARAM_BOOLEAN = 133701
PARAM_ZINTEGER = 133702
PARAM_STRING = 133703
PARAM_ENUM = 133704
PARAM_AUTO_BOOLEAN = 133705
COMMAND_USER = 133706
COMPLETE_EXPRESSION = 133707
PARAM_OPTIONAL_FILENAME = 133708
COMMAND_SUPPORT = 133709
TYPE_CODE_STRUCT = 133710

class Parameter():
    def __init__(self, name, type, cls, seq=None):
        pass

events = SimpleNamespace()

class EventRegistry():
    def connect(self, _):
        pass

    pass

def execute(s, to_string=False, from_tty=False):
    if s == "show language":
        return 'The current source language is "auto; currently c".'
    elif s == "show debug-file-directory":
        return 'The directory where separate debug symbols are searched for is "/usr/lib/debug".'
    elif s == "show pagination":
        return 'State of pagination is off.'
    elif s == "help all":
        return 'there-are-no-command-why-are-you-asking-me -- Why?\n'
    elif s == "show endian":
        return f'The target endianness is set automatically (currently little {pyda.arch.endianness()}).'
    elif s == "show architecture":
        return f"The target architecture is set automatically (currently {pyda.arch.gdb_arch()})",
    elif s == "show osabi":
        return {
            "linux": """The current OS ABI is "auto" (currently "GNU/Linux").
The default OS ABI is "GNU/Linux".
"""
        }[pyda.arch.os()]
    elif s == "info win":
        return "No stack."
    elif s.startswith("set "):
        return "The TUI is not active."
    elif s.startswith("handle "):
        return "The TUI is not active."
    else:
        print(f"Failed command: {s}")
        raise NotImplementedError(f"s={s}")

class Type:
    def __init__(self, sz, signed, float=False):
        self.sz = sz
        self.signed = signed
        self.float = float

    def pointer(self):
        return Pointer(self)

    @property
    def sizeof(self):
        return self.sz

    @property
    def alignof(self):
        return self.sz

    def array(self, n):
        return Array(self, n)

    def __eq__(self, other):
        if not isinstance(other, Type):
            return False

        return (
            self.sz == other.sz
            and self.signed == other.signed
            and self.float == other.float
        )

class Pointer(Type):
    def __init__(self, t):
        super().__init__(8, False)
        self._points_to = t

    def __eq__(self, other):
        if not isinstance(other, Pointer):
            return False

        return self._points_to == other._points_to

class Array(Type):
    def __init__(self, t, n):
        super().__init__(t.sz * n, t.signed)
        self._points_to = t
        self._n = n

    def __eq__(self, other):
        if not isinstance(other, Array):
            return False

        return self._points_to == other._points_to and self._n == other._n

    def target(self):
        return self._points_to

class Value:
    def __init__(self, v):
        self.v = v
        self.type = Type(0, False)

    def cast(self, t):
        v = Value(self.v)
        v.type = t
        return v

    def __int__(self):
        assert not isinstance(self.type, Array)
        assert not self.type.float
        if type(self.v) is int:
            return self.v
        elif type(self.v) is bytes:
            return int.from_bytes(self.v, pyda.arch.endianness())
        else:
            raise NotImplementedError(f"Value: {self.v}")

    def __getitem__(self, idx):
        assert isinstance(self.type, Array), f"type: {self.type.__class__} {Array}"
        assert type(self.v) is bytes
        assert idx < self.type._n

        elementsz = self.type.target().sz
        return Value(self.v[idx * elementsz:(idx + 1) * elementsz]).cast(self.type.target())

class Command():
    def __init__(self, name, command_class, completer_class, prefix=None):
        self.name = name
        self.command_class = command_class
        self.prefix = prefix

class Function():
    def __init__(self, name):
        self.name = name

class Breakpoint():
    def __init__(self):
        pass

class error(BaseException):
    def __init__(self, s):
        self.s = s

    def __str__(self):
        return self.s

MemoryError = pyda.MemoryError

VERSION = "12.1"

def lookup_type(s):
    match s:
        case "char":
            return Type(1, True)
        case "short":
            return Type(2, True)
        case "int":
            return Type(4, True)
        case "long":
            return Type(8, True)
        case "long long":
            return Type(8, True)
        case "unsigned char":
            return Type(1, False)
        case "unsigned short":
            return Type(2, False)
        case "unsigned int":
            return Type(4, False)
        case "unsigned long":
            return Type(8, False)
        case "unsigned long long":
            return Type(8, False)
        case "long double":
            return Type(16, True, float=True)
        case "()" | "void":
            return Type(0, False)
        case _:
            print(f"lookup_type: {s}")
            return None
            # raise NotImplementedError(f"cmd: {s}")


events.exited = EventRegistry()
events.cont = EventRegistry()
events.new_objfile = EventRegistry()
events.stop = EventRegistry()
events.start = EventRegistry()
events.new_thread = EventRegistry()
events.before_prompt = EventRegistry()
events.memory_changed = EventRegistry()
events.register_changed = EventRegistry()

class Thread():
    def __init__(self, tid):
        self.tid = tid

    @property
    def global_num(self):
        return self.tid

class Frame():
    def architecture(self):
        return GdbArch(pyda.arch.gdb_arch())

class GdbArch():
    def __init__(self, s):
        self.s = s

    def name(self):
        return self.s

def newest_frame():
    return Frame()

def selected_thread():
    return Thread(pyda_core.get_current_thread_id())

class types():
    def has_field(t, name):
        return name in t.keys()
