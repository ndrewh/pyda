import pyda_core
import ctypes

class Expr:
    # it is NOT legal for user code to call this constructor EVER
    def __init__(self, handle):
        self._handle = handle

    def __add__(self, other):
        us = self.expr_from(self)
        other = self.expr_from(other)
        return Expr(pyda_core.expr(pyda_core.EXPR_TYPE_ADD, us._handle, other._handle))

    def __sub__(self, other):
        us = self.expr_from(self)
        other = self.expr_from(other)
        return Expr(pyda_core.expr(pyda_core.EXPR_TYPE_SUB, us._handle, other._handle))

    def __mul__(self, other):
        us = self.expr_from(self)
        other = self.expr_from(other)
        return Expr(pyda_core.expr(pyda_core.EXPR_TYPE_MUL, us._handle, other._handle))

    def __floordiv__(self, other):
        us = self.expr_from(self)
        other = self.expr_from(other)
        return Expr(pyda_core.expr(pyda_core.EXPR_TYPE_DIV, us._handle, other._handle))

    def __mod__(self, other):
        us = self.expr_from(self)
        other = self.expr_from(other)
        return Expr(pyda_core.expr(pyda_core.EXPR_TYPE_MOD, us._handle, other._handle))

    def __del__(self):
        if self._handle is not None:
            pyda_core.free_expr(self._handle)

    @staticmethod
    def expr_from(val):
        if isinstance(val, Global):
            return val.val
        elif isinstance(val, Expr):
            return val
        elif isinstance(val, int):
            return Expr(pyda_core.expr(pyda_core.EXPR_TYPE_CONST, val, 0))
        else:
            raise ValueError(f"Invalid type for expression {type(val)}")


class Builder:
    def __init__(self, handle):
        self._b = handle
        self.regs = BuilderRegisters(handle)

    def load(self, addr):
        addr = Expr.expr_from(addr)
        return Expr(pyda_core.expr(pyda_core.EXPR_TYPE_LOAD, addr._handle, 0))

    def store(self, addr, value):
        addr = Expr.expr_from(addr)
        value = Expr.expr_from(value)
        return Expr(pyda_core.expr(pyda_core.EXPR_TYPE_STORE, addr._handle, value._handle))

    def constant(self, value):
        return Expr(pyda_core.expr(pyda_core.EXPR_TYPE_CONST, value, 0))

    def raw(self, insns):
        return Expr(pyda_core.expr_raw(insns))

    def debug(self):
        self._b.print()

class BuilderRegisters():
    def __init__(self, b):
        self._b = b

    def __getitem__(self, name):
        val = None
        reg_id = getattr(pyda_core, "REG_"+name.upper(), None)
        if reg_id:
            val = Expr(self._b.get_register(reg_id))

        if val is not None:
            return val

        raise AttributeError(f"Invalid register name '{name}'")

    def __setitem__(self, name, value):
        reg_id = getattr(pyda_core, "REG_"+name.upper(), None)
        if reg_id:
            expr = Expr.expr_from(value)
            self._b.set_register(reg_id, expr._handle)
        else:
            raise AttributeError(f"Invalid register name '{name}'")

    def __getattr__(self, name):
        return self[name]

    def __setattr__(self, name, value):
        if name != "_b":
            self[name] = value
        else:
            super().__setattr__(name, value)

    def has_reg(self, name):
        return hasattr(pyda_core, "REG_"+name.upper())

class Global(Expr):
    def __init__(self, cval):
        self._handle = None
        self._cval = cval
        self._element_sz = ctypes.sizeof(cval)
        if isinstance(cval, ctypes.Array):
            self._element_sz = ctypes.sizeof(cval._type_)

    @property
    def val(self):
        return Builder.load(None, ctypes.addressof(self._cval))

    @val.setter
    def val(self, value):
        Builder.store(None, ctypes.addressof(self._cval), value)

    def __getitem__(self, key):
        if isinstance(key, int):
            addr = key * self._element_sz + ctypes.addressof(self._cval)
        else:
            addr = (Expr.expr_from(key) * self._element_sz) + ctypes.addressof(self._cval)

        return Builder.load(None, addr)

    def __setitem__(self, key, val):
        if isinstance(key, int):
            addr = key * self._element_sz + ctypes.addressof(self._cval)
        else:
            addr = (Expr.expr_from(key) * self._element_sz) + ctypes.addressof(self._cval)

        Builder.store(None, addr, val)

    def __int__(self):
        return int(self._cval)

    def __str__(self):
        return f"Global({str(self._cval)})"

    def __repr__(self):
        return f"Global({repr(self._cval)})"

    @property
    def cval(self):
        return self._cval






