#include "pyda_core_py.h"
#include "pyda_core.h"
#include "pyda_threads.h"
#include "util.h"

#include <Python.h>

#ifdef PYDA_DYNAMORIO_CLIENT
#include "dr_api.h"
#endif

int is_dynamorio_running = 0;

typedef struct {
    PyObject_HEAD
    pyda_thread *main_thread; // main thread
} PydaProcess;

static PyObject* pyda_core_process(PyObject *self, PyObject *args, PyObject *kwargs);
static PyObject *pyda_list_modules(PyObject *self, PyObject *noarg);
static PyObject *pyda_get_base(PyObject *self, PyObject *args);
static PyObject *pyda_get_module_for_addr(PyObject *self, PyObject *args);
static PyObject *pyda_get_current_thread_id(PyObject *self, PyObject *noarg);

static void PydaProcess_dealloc(PydaProcess *self);
static PyObject *PydaProcess_run(PyObject *self, PyObject *noarg);
static PyObject *PydaProcess_run_until_io(PyObject *self, PyObject *noarg);
static PyObject *PydaProcess_run_until_pc(PyObject *self, PyObject *arg);
static PyObject *PydaProcess_get_io_fds(PyObject *self, PyObject *noarg);
static PyObject *PydaProcess_register_hook(PyObject *self, PyObject *args);
static PyObject *PydaProcess_unregister_hook(PyObject *self, PyObject *args);
static PyObject *PydaProcess_set_thread_init_hook(PyObject *self, PyObject *args);
static PyObject *PydaProcess_get_register(PyObject *self, PyObject *args);
static PyObject *PydaProcess_set_register(PyObject *self, PyObject *args);
static PyObject *PydaProcess_read(PyObject *self, PyObject *args);
static PyObject *PydaProcess_write(PyObject *self, PyObject *args);
static PyObject *PydaProcess_get_main_module(PyObject *self, PyObject *args);
static PyObject *PydaProcess_set_syscall_filter(PyObject *self, PyObject *args);
static PyObject *PydaProcess_set_syscall_pre_hook(PyObject *self, PyObject *args);
static PyObject *PydaProcess_set_syscall_post_hook(PyObject *self, PyObject *args);

static PyMethodDef PydaGlobalMethods[] = {
    {"process",  (PyCFunction)pyda_core_process, METH_KEYWORDS | METH_VARARGS,
     "Start a process."},
    {"list_modules",  (PyCFunction)pyda_list_modules, METH_NOARGS,
     "List all the modules."},
    {"get_base",  (PyCFunction)pyda_get_base, METH_VARARGS,
     "Get base address for module"},
    {"get_module_for_addr",  (PyCFunction)pyda_get_module_for_addr, METH_VARARGS,
     "Get module info for addr"},
    {"get_current_thread_id",  (PyCFunction)pyda_get_current_thread_id, METH_NOARGS,
     "Get current thread id, numbered from 1"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef pyda_module = {
    PyModuleDef_HEAD_INIT,
    "pyda_core",   /* name of module */
    NULL, /* module documentation, may be NULL */
    -1,       /* size of per-interpreter state of the module,
                 or -1 if the module keeps state in global variables. */
    PydaGlobalMethods
};

static PyObject *MemoryError;

PyMODINIT_FUNC
PyInit_pyda_core(void) {
    PyObject *m = PyModule_Create(&pyda_module);
    MemoryError = PyErr_NewException("pyda.MemoryError", NULL, NULL);
    Py_XINCREF(MemoryError);
    if (PyModule_AddObject(m, "MemoryError", MemoryError) < 0) {
        Py_XDECREF(MemoryError);
        Py_CLEAR(MemoryError);
        Py_DECREF(m);
        return NULL;
    }

#ifdef X86
    PyModule_AddIntConstant(m, "REG_RAX", DR_REG_RAX);
    PyModule_AddIntConstant(m, "REG_RBX", DR_REG_RBX);
    PyModule_AddIntConstant(m, "REG_RCX", DR_REG_RCX);
    PyModule_AddIntConstant(m, "REG_RDX", DR_REG_RDX);
    PyModule_AddIntConstant(m, "REG_RSI", DR_REG_RSI);
    PyModule_AddIntConstant(m, "REG_RDI", DR_REG_RDI);
    PyModule_AddIntConstant(m, "REG_RBP", DR_REG_RBP);
    PyModule_AddIntConstant(m, "REG_RSP", DR_REG_RSP);
    PyModule_AddIntConstant(m, "REG_R8", DR_REG_R8);
    PyModule_AddIntConstant(m, "REG_R9", DR_REG_R9);
    PyModule_AddIntConstant(m, "REG_R10", DR_REG_R10);
    PyModule_AddIntConstant(m, "REG_R11", DR_REG_R11);
    PyModule_AddIntConstant(m, "REG_R12", DR_REG_R12);
    PyModule_AddIntConstant(m, "REG_R13", DR_REG_R13);
    PyModule_AddIntConstant(m, "REG_R14", DR_REG_R14);
    PyModule_AddIntConstant(m, "REG_R15", DR_REG_R15);
    PyModule_AddIntConstant(m, "REG_RIP", PYDA_REG_PC);
    PyModule_AddIntConstant(m, "REG_PC", PYDA_REG_PC);
    PyModule_AddIntConstant(m, "REG_FSBASE", PYDA_REG_FSBASE);
    PyModule_AddIntConstant(m, "REG_XMM0", DR_REG_XMM0);
    PyModule_AddIntConstant(m, "REG_XMM1", DR_REG_XMM1);
    PyModule_AddIntConstant(m, "REG_XMM2", DR_REG_XMM2);
    PyModule_AddIntConstant(m, "REG_XMM3", DR_REG_XMM3);
    PyModule_AddIntConstant(m, "REG_XMM4", DR_REG_XMM4);
    PyModule_AddIntConstant(m, "REG_XMM5", DR_REG_XMM5);
    PyModule_AddIntConstant(m, "REG_XMM6", DR_REG_XMM6);
    PyModule_AddIntConstant(m, "REG_XMM7", DR_REG_XMM7);
#elif ARM64
    PyModule_AddIntConstant(m, "REG_X0", DR_REG_X0);
    PyModule_AddIntConstant(m, "REG_X1", DR_REG_X1);
    PyModule_AddIntConstant(m, "REG_X2", DR_REG_X2);
    PyModule_AddIntConstant(m, "REG_X3", DR_REG_X3);
    PyModule_AddIntConstant(m, "REG_X4", DR_REG_X4);
    PyModule_AddIntConstant(m, "REG_X5", DR_REG_X5);
    PyModule_AddIntConstant(m, "REG_X6", DR_REG_X6);
    PyModule_AddIntConstant(m, "REG_X7", DR_REG_X7);
    PyModule_AddIntConstant(m, "REG_X8", DR_REG_X8);
    PyModule_AddIntConstant(m, "REG_X9", DR_REG_X9);
    PyModule_AddIntConstant(m, "REG_X10", DR_REG_X10);
    PyModule_AddIntConstant(m, "REG_X11", DR_REG_X11);
    PyModule_AddIntConstant(m, "REG_X12", DR_REG_X12);
    PyModule_AddIntConstant(m, "REG_X13", DR_REG_X13);
    PyModule_AddIntConstant(m, "REG_X14", DR_REG_X14);
    PyModule_AddIntConstant(m, "REG_X15", DR_REG_X15);
    PyModule_AddIntConstant(m, "REG_X16", DR_REG_X16);
    PyModule_AddIntConstant(m, "REG_X17", DR_REG_X17);
    PyModule_AddIntConstant(m, "REG_X18", DR_REG_X18);
    PyModule_AddIntConstant(m, "REG_X19", DR_REG_X19);
    PyModule_AddIntConstant(m, "REG_X20", DR_REG_X20);
    PyModule_AddIntConstant(m, "REG_X21", DR_REG_X21);
    PyModule_AddIntConstant(m, "REG_X22", DR_REG_X22);
    PyModule_AddIntConstant(m, "REG_X23", DR_REG_X23);
    PyModule_AddIntConstant(m, "REG_X24", DR_REG_X24);
    PyModule_AddIntConstant(m, "REG_X25", DR_REG_X25);
    PyModule_AddIntConstant(m, "REG_X26", DR_REG_X26);
    PyModule_AddIntConstant(m, "REG_X27", DR_REG_X27);
    PyModule_AddIntConstant(m, "REG_X28", DR_REG_X28);
    PyModule_AddIntConstant(m, "REG_X29", DR_REG_X29);
    PyModule_AddIntConstant(m, "REG_X30", DR_REG_X30);
    PyModule_AddIntConstant(m, "REG_SP", DR_REG_SP);
    PyModule_AddIntConstant(m, "REG_PC", PYDA_REG_PC);
#endif

    return m;
}

/* Process class */

static PyMethodDef PydaProcessMethods[] = {
    {"run",  PydaProcess_run, METH_NOARGS, "Run"},
    {"run_until_pc",  PydaProcess_run_until_pc, METH_VARARGS, "Run until PC is reached"},
    {"run_until_io",  PydaProcess_run_until_io, METH_NOARGS, "Run until IO syscall"},
    {"get_io_fds", PydaProcess_get_io_fds, METH_NOARGS, "Get IO fds"},
    {"register_hook",  PydaProcess_register_hook, METH_VARARGS, "Register a hook"},
    {"unregister_hook",  PydaProcess_unregister_hook, METH_VARARGS, "Un-register a hook"},
    {"set_thread_init_hook",  PydaProcess_set_thread_init_hook, METH_VARARGS, "Register thread init hook"},
    {"get_register",  PydaProcess_get_register, METH_VARARGS, "Get a specific register"},
    {"set_register",  PydaProcess_set_register, METH_VARARGS, "Set a specific register"},
    {"get_main_module",  PydaProcess_get_main_module, METH_VARARGS, "Get name of main module"},
    {"read",  PydaProcess_read, METH_VARARGS, "Read memory"},
    {"write",  PydaProcess_write, METH_VARARGS, "Write memory"},
    // {"set_syscall_filter",  PydaProcess_set_syscall_filter, METH_VARARGS, "Set list of syscalls to call hooks on"},
    {"set_syscall_pre_hook",  PydaProcess_set_syscall_pre_hook, METH_VARARGS, "Register syscall pre hook"},
    {"set_syscall_post_hook",  PydaProcess_set_syscall_post_hook, METH_VARARGS, "Register syscall post hook"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyTypeObject PydaProcess_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "custom.Custom",
    .tp_doc = PyDoc_STR("Custom objects"),
    .tp_basicsize = sizeof(PydaProcess),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyType_GenericNew,
    .tp_dealloc = (destructor)PydaProcess_dealloc,
    .tp_methods = PydaProcessMethods,
};


static PyObject *
pyda_core_process(PyObject *self, PyObject *args, PyObject *kwargs) {
    ABORT_IF_NODYNAMORIO;

    const char *name;
    PydaProcess *result = NULL;

    Py_buffer bin_path;

    static char *kwlist[] = {"name", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s*", kwlist, &bin_path))
        return NULL;
    
    *(char*)(bin_path.buf + bin_path.len) = '\0';

    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (t != t->proc->main_thread) {
        PyErr_SetString(PyExc_RuntimeError, "Only the main thread is currently allowed to call process().");
        return NULL;
    }

    if (t->proc->py_obj) {
        PyErr_SetString(PyExc_RuntimeError, "You may only call process() once");
        return NULL;
    }

    PyType_Ready(&PydaProcess_Type);
    result = PyObject_NEW(PydaProcess, &PydaProcess_Type);
    if (result != NULL)
        result->main_thread = t;
    
    t->proc->py_obj = (PyObject*)result;

    PyBuffer_Release(&bin_path);
    return (PyObject*)result;
}

static PyObject *
PydaProcess_run(PyObject* self, PyObject *noarg) {
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);

    Py_BEGIN_ALLOW_THREADS
    pyda_yield(t);
#ifdef PYDA_DYNAMORIO_CLIENT
    DEBUG_PRINTF("yield returned\n");
#endif // PYDA_DYNAMORIO_CLIENT
    Py_END_ALLOW_THREADS

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
PydaProcess_run_until_io(PyObject* self, PyObject *noarg) {
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    t->python_blocked_on_io = 1;

    // todo: assert that this thread is like, actually blocked

    Py_BEGIN_ALLOW_THREADS
    pyda_yield(t);
#ifdef PYDA_DYNAMORIO_CLIENT
    DEBUG_PRINTF("yield after io returned\n");
#endif // PYDA_DYNAMORIO_CLIENT
    Py_END_ALLOW_THREADS

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
PydaProcess_get_io_fds(PyObject* self, PyObject *noarg) {
    PydaProcess *p = (PydaProcess*)self;
    pyda_process *proc = p->main_thread->proc;

    PyObject *list = PyList_New(0);
    PyList_Append(list, PyLong_FromLong(proc->stdin_fd));
    PyList_Append(list, PyLong_FromLong(proc->stdout_fd));
    PyList_Append(list, PyLong_FromLong(proc->stderr_fd));

    return list;
}

static PyObject *
PydaProcess_run_until_pc(PyObject* self, PyObject *args) {
    PyErr_SetString(PyExc_RuntimeError, "Not implemented");
    return NULL;

    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    t->python_blocked_on_io = 1;

    unsigned long addr;

    if (!PyArg_ParseTuple(args, "K", &addr))
        return NULL;

    Py_BEGIN_ALLOW_THREADS
    // t->python_blocked_until = addr;
    pyda_yield(t);
#ifdef PYDA_DYNAMORIO_CLIENT
    DEBUG_PRINTF("yield returned\n");
#endif // PYDA_DYNAMORIO_CLIENT
    Py_END_ALLOW_THREADS

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
pyda_list_modules(PyObject* self, PyObject *noarg) {
#ifdef PYDA_DYNAMORIO_CLIENT
    PyObject *list = PyList_New(0);
    dr_module_iterator_t *iter = dr_module_iterator_start();
    while (dr_module_iterator_hasnext(iter)) {
        module_data_t *mod = dr_module_iterator_next(iter);
        PyList_Append(list, PyUnicode_FromString(mod->full_path));
    }
    dr_module_iterator_stop(iter);
    return list;
#endif // PYDA_DYNAMORIO_CLIENT

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
pyda_get_current_thread_id(PyObject* self, PyObject *noarg) {
#ifdef PYDA_DYNAMORIO_CLIENT
    int tid = ((pyda_thread*)pyda_thread_getspecific(g_pyda_tls_idx))->tid;
    return PyLong_FromLong(tid);
#endif // PYDA_DYNAMORIO_CLIENT

    Py_INCREF(Py_None);
    return Py_None;
}

static void
PydaProcess_dealloc(PydaProcess *self)
{
    Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject *
PydaProcess_get_register(PyObject *self, PyObject *args) {
    PydaProcess *p = (PydaProcess*)self;
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);

    unsigned long long reg_id;

    if (!PyArg_ParseTuple(args, "K", &reg_id))
        return NULL;

#ifdef PYDA_DYNAMORIO_CLIENT
    // DEBUG_PRINTF("get_register: %s\n", regname);
    dr_mcontext_t *mc = &t->cur_context;

    // TODO: Fix... copilot wrote this. Surely we can write
    // a macro...

    if (reg_id == PYDA_REG_PC) {
        return PyLong_FromUnsignedLong((unsigned long)mc->pc);
    } else if (reg_id == PYDA_REG_FSBASE) {
        return PyLong_FromUnsignedLong((unsigned long)dr_get_tls_field(dr_get_current_drcontext()));
    }

    opnd_size_t sz = reg_get_size(reg_id);
    if (!(sz == OPSZ_4 || sz == OPSZ_8 || sz == OPSZ_16 || sz == OPSZ_32)) {
        PyErr_SetString(PyExc_RuntimeError, "Unsupported register size");
        return NULL;
    }

    uint64_t val[4] = {0};
    reg_get_value_ex(reg_id, mc, (uint8_t*)&val);

    if (sz == OPSZ_8) {
        // fast path
        return PyLong_FromUnsignedLong(val[0]);
    }

    // Convert to decimal string
    char buf[64];
    if (snprintf(buf, sizeof(buf), "0x%lx%lx", val[1], val[0]) >= sizeof(buf)) {
        PyErr_SetString(PyExc_RuntimeError, "Internal error: reg buffer too small");
        return NULL;
    }

    PyObject *ret = PyLong_FromString(buf, NULL, 16);
    if (!ret) {
        PyErr_SetString(PyExc_RuntimeError, "Internal error: failed to convert string to long");
        return NULL;
    }

    return ret;

#endif // PYDA_DYNAMORIO_CLIENT

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
PydaProcess_set_register(PyObject *self, PyObject *args) {
    PydaProcess *p = (PydaProcess*)self;
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);

    unsigned long long reg_id;
    PyObject *val;

    if (!PyArg_ParseTuple(args, "KO", &reg_id, &val))
        return NULL;

    if (!PyLong_Check(val)) {
        PyErr_SetString(PyExc_RuntimeError, "Value must be an integer");
        return NULL;
    }

#ifdef PYDA_DYNAMORIO_CLIENT
    // DEBUG_PRINTF("get_register: %s\n", regname);
    dr_mcontext_t *mc = &t->cur_context;

    uint64_t raw[4] = {0};
    _PyLong_AsByteArray((PyLongObject *)val, (unsigned char*)&raw, sizeof(raw), 1, 0);

    DEBUG_PRINTF("set_register: %llx %llx\n", reg_id, raw[0]);

    if (reg_id == PYDA_REG_PC) {
        mc->pc = (void*)raw[0];
        t->rip_updated_in_cleancall = 1;
    } else {
        if (!reg_set_value_ex(reg_id, mc, (uint8_t*)&raw)) {
            PyErr_SetString(PyExc_RuntimeError, "Failed to set register");
            return NULL;
        }
    }


#endif // PYDA_DYNAMORIO_CLIENT

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
PydaProcess_register_hook(PyObject *self, PyObject *args) {
    PydaProcess *p = (PydaProcess*)self;

    unsigned long long addr;
    PyObject *callback;

    if (!PyArg_ParseTuple(args, "KO!", &addr, &PyFunction_Type, &callback))
        return NULL;

    PyCodeObject *code = (PyCodeObject*)PyFunction_GetCode(callback);
    if (!code || code->co_argcount != 1) {
        PyErr_SetString(PyExc_RuntimeError, "Callback must take one argument");
        return NULL;
    }

#ifdef PYDA_DYNAMORIO_CLIENT
    DEBUG_PRINTF("register_hook: %llx\n", addr);
#endif // PYDA_DYNAMORIO_CLIENT
    pyda_add_hook(p->main_thread->proc, addr, callback);

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
PydaProcess_set_thread_init_hook(PyObject *self, PyObject *args) {
    PydaProcess *p = (PydaProcess*)self;

    PyObject *callback;

    if (!PyArg_ParseTuple(args, "O!", &PyFunction_Type, &callback))
        return NULL;

    PyCodeObject *code = (PyCodeObject*)PyFunction_GetCode(callback);
    if (!code || code->co_argcount != 1) {
        PyErr_SetString(PyExc_RuntimeError, "Callback must take one argument");
        return NULL;
    }
#ifdef PYDA_DYNAMORIO_CLIENT
    DEBUG_PRINTF("set_thread_init_hook\n");
#endif

    // note: pyda_set_thread_init_hook calls incref
    pyda_set_thread_init_hook(p->main_thread->proc, callback);

    Py_INCREF(Py_None);
    return Py_None;
}
static PyObject *
PydaProcess_set_syscall_pre_hook(PyObject *self, PyObject *args) {
    PydaProcess *p = (PydaProcess*)self;

    PyObject *callback;

    if (!PyArg_ParseTuple(args, "O!", &PyFunction_Type, &callback))
        return NULL;

    PyCodeObject *code = (PyCodeObject*)PyFunction_GetCode(callback);
    if (!code || code->co_argcount != 2) {
        PyErr_SetString(PyExc_RuntimeError, "Callback must take two arguments");
        return NULL;
    }

#ifdef PYDA_DYNAMORIO_CLIENT
    DEBUG_PRINTF("set_syscall_pre_hook\n");
#endif

    // note: pyda_set_syscall_pre_hook calls incref
    pyda_set_syscall_pre_hook(p->main_thread->proc, callback);

    Py_INCREF(Py_None);
    return Py_None;
}
static PyObject *
PydaProcess_set_syscall_post_hook(PyObject *self, PyObject *args) {
    PydaProcess *p = (PydaProcess*)self;

    PyObject *callback;

    if (!PyArg_ParseTuple(args, "O!", &PyFunction_Type, &callback))
        return NULL;

    PyCodeObject *code = (PyCodeObject*)PyFunction_GetCode(callback);
    if (!code || code->co_argcount != 2) {
        PyErr_SetString(PyExc_RuntimeError, "Callback must take two arguments");
        return NULL;
    }

#ifdef PYDA_DYNAMORIO_CLIENT
    DEBUG_PRINTF("set_syscall_post_hook\n");
#endif

    // note: pyda_set_syscall_pre_hook calls incref
    pyda_set_syscall_post_hook(p->main_thread->proc, callback);

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
PydaProcess_unregister_hook(PyObject *self, PyObject *args) {
    PydaProcess *p = (PydaProcess*)self;

    unsigned long long addr;

    if (!PyArg_ParseTuple(args, "K", &addr)) {
        return NULL;
    }

#ifdef PYDA_DYNAMORIO_CLIENT
    DEBUG_PRINTF("unregister_hook: %llx\n", addr);
#endif // PYDA_DYNAMORIO_CLIENT
    pyda_remove_hook(p->main_thread->proc, addr);

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
PydaProcess_get_main_module(PyObject *self, PyObject *args) {
    const char *name;

    if (!PyArg_ParseTuple(args, ""))
        return NULL;
    
    PyObject *result = NULL;
    
#ifdef PYDA_DYNAMORIO_CLIENT
    module_data_t *mod = dr_get_main_module();

    if (!mod) {
        PyErr_SetString(PyExc_RuntimeError, "Module not found");
        return NULL;
    }

    // Return a string with the name of the main module
    result = PyUnicode_FromString(mod->full_path);
#else
    PyErr_SetString(PyExc_RuntimeError, "Not implemented outside of dynamorio");
    return NULL;
#endif

    return (PyObject*)result;
}


static PyObject *
pyda_get_base(PyObject *self, PyObject *args) {
    const char *name;

    Py_buffer bin_path;

    if (!PyArg_ParseTuple(args, "s*", &bin_path))
        return NULL;
    
    *(char*)(bin_path.buf + bin_path.len) = '\0';

    PyObject *result = NULL;
    
#ifdef PYDA_DYNAMORIO_CLIENT
    dr_module_iterator_t *iter = dr_module_iterator_start();
    while (dr_module_iterator_hasnext(iter)) {
        module_data_t *mod = dr_module_iterator_next(iter);
        if (strstr(mod->full_path, bin_path.buf)) {
            // Return the base address as python number
            result = PyLong_FromUnsignedLong((unsigned long)mod->start);
            break;
        }
    }

    if (!result) {
        PyErr_SetString(PyExc_RuntimeError, "Module not found");
        return NULL;
    }
#else
    PyErr_SetString(PyExc_RuntimeError, "Not implemented outside of dynamorio");
    return NULL;
#endif
    PyBuffer_Release(&bin_path);

    return (PyObject*)result;
}

static PyObject *
pyda_get_module_for_addr(PyObject *self, PyObject *args) {
    unsigned long addr;
    if (!PyArg_ParseTuple(args, "K", &addr))
        return NULL;
    
    PyObject *result = NULL;
    
#ifdef PYDA_DYNAMORIO_CLIENT
    unsigned char *base;
    size_t size;
    unsigned int prot;
    unsigned long perms = 0;
    if (dr_query_memory((void*)addr, &base, &size, &prot)) {
        if (prot & DR_MEMPROT_READ) {
            perms |= 4;
        }
        if (prot & DR_MEMPROT_WRITE) {
            perms |= 2;
        }
        if (prot & DR_MEMPROT_EXEC) {
            perms |= 1;
        }
    }

    result = PyList_New(0);
    module_data_t *mod = dr_lookup_module((void*)addr);
    if (mod) {
        PyList_Append(result, PyUnicode_FromString(mod->full_path));
        PyList_Append(result, PyLong_FromUnsignedLong((unsigned long)mod->start));
        PyList_Append(result, PyLong_FromUnsignedLong((unsigned long)mod->end));
        PyList_Append(result, PyLong_FromUnsignedLong(perms));

        dr_free_module_data(mod);
        return result;
    } else {
        PyList_Append(result, PyUnicode_FromString("unknown"));
        PyList_Append(result, PyLong_FromUnsignedLong((unsigned long)base));
        PyList_Append(result, PyLong_FromUnsignedLong((unsigned long)base + size));
        PyList_Append(result, PyLong_FromUnsignedLong(perms));
        return result;
    }

#else
    PyErr_SetString(PyExc_RuntimeError, "Not implemented outside of dynamorio");
    return NULL;
#endif

    Py_INCREF(Py_None);
    return Py_None;
}


static PyObject *
PydaProcess_read(PyObject *self, PyObject *args) {
    PydaProcess *p = (PydaProcess*)self;


    unsigned long addr;
    unsigned long count;
    if (!PyArg_ParseTuple(args, "KK", &addr, &count))
        return NULL;

    if (count > 0x1000000) {
        PyErr_SetString(PyExc_RuntimeError, "Unreasonable read size");
        return NULL;
    }

#ifdef PYDA_DYNAMORIO_CLIENT
    // DEBUG_PRINTF("read: %lx %lx\n", addr, count);
    void *buf = malloc(count);
    int success = dr_safe_read((void*)addr, count, buf, NULL);
    if (!success) {
        PyErr_SetString(MemoryError, "Failed to read memory");
        free(buf);
        return NULL;
    }
    PyObject *result = PyBytes_FromStringAndSize(buf, count);
    free(buf);
    return result;
#endif // PYDA_DYNAMORIO_CLIENT

    Py_INCREF(Py_None);
    return Py_None;
}


static PyObject *
PydaProcess_write(PyObject *self, PyObject *args) {
    PydaProcess *p = (PydaProcess*)self;


    unsigned long addr;
    const char *data;
    Py_ssize_t len;
    if (!PyArg_ParseTuple(args, "Ks#", &addr, &data, &len))
        return NULL;

    if (len > 0x1000000) {
        PyErr_SetString(PyExc_RuntimeError, "Unreasonable write size");
        return NULL;
    }

#ifdef PYDA_DYNAMORIO_CLIENT
    DEBUG_PRINTF("write: %lx %lx\n", addr, len);
    int success = dr_safe_write((void*)addr, len, data, NULL);
    if (!success) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to write memory");
        return NULL;
    }
#endif // PYDA_DYNAMORIO_CLIENT

    Py_INCREF(Py_None);
    return Py_None;
}