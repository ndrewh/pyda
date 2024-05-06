from collections import namedtuple

class Process():
    def __init__(self, handle):
        self._p = handle
    
    def hook(self, addr, callback):
        hook_wrapper = lambda p, a: callback(self, a)
        self._p.register_hook(addr, hook_wrapper)
    
    def read(self, addr, size):
        return self._p.read(addr, size)

    def write(self, addr, data):
        return self._p.write(addr, data)
    
    def __getattr__(self, name):
        # TODO: Move these into CPython extension
        if name in "regs":
            return ProcessRegisters(self._p)
        elif name == "mem":
            return ProcessMemory(self)
        elif name == "maps":
            return ProcessMaps(self._p)
        elif name == "exe_path":
            return self._p.get_main_module()

        raise AttributeError(f"Invalid attribute '{name}'")
    
    def run(self):
        self._p.run()

class ProcessRegisters():
    def __init__(self, p):
        self._p = p

    def __getitem__(self, name):
        val = self._p.get_register(name.lower())
        if val is not None:
            return val
        
        raise AttributeError(f"Invalid register name '{name}'")

    def __getattr__(self, name):
        return self[name]

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

Map = namedtuple("Map", ("base",))
class ProcessMaps():
    def __init__(self, p):
        self._p = p
    
    def __getitem__(self, key):
        return Map(base=self._p.get_base(key))

        