#define PY_SSIZE_T_CLEAN
#include <Python.h>
PyMODINIT_FUNC PyInit_pyda_core(void);

#define PYDA_REG_PC 0xb33f0001
#define PYDA_REG_FSBASE 0xb33f0002