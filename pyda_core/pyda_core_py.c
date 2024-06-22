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
static PyObject *PydaProcess_register_hook(PyObject *self, PyObject *args);
static PyObject *PydaProcess_unregister_hook(PyObject *self, PyObject *args);
static PyObject *PydaProcess_set_thread_init_hook(PyObject *self, PyObject *args);
static PyObject *PydaProcess_get_register(PyObject *self, PyObject *args);
static PyObject *PydaProcess_set_register(PyObject *self, PyObject *args);
static PyObject *PydaProcess_read(PyObject *self, PyObject *args);
static PyObject *PydaProcess_write(PyObject *self, PyObject *args);
static PyObject *PydaProcess_get_main_module(PyObject *self, PyObject *args);

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

    return m;
}

/* Process class */

static PyMethodDef PydaProcessMethods[] = {
    {"run",  PydaProcess_run, METH_NOARGS, "Run"},
    {"register_hook",  PydaProcess_register_hook, METH_VARARGS, "Register a hook"},
    {"unregister_hook",  PydaProcess_unregister_hook, METH_VARARGS, "Un-register a hook"},
    {"set_thread_init_hook",  PydaProcess_set_thread_init_hook, METH_VARARGS, "Register thread init hook"},
    {"get_register",  PydaProcess_get_register, METH_VARARGS, "Get a specific register"},
    {"set_register",  PydaProcess_set_register, METH_VARARGS, "Set a specific register"},
    {"get_main_module",  PydaProcess_get_main_module, METH_VARARGS, "Get name of main module"},
    {"read",  PydaProcess_read, METH_VARARGS, "Read memory"},
    {"write",  PydaProcess_write, METH_VARARGS, "Write memory"},
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

    PyType_Ready(&PydaProcess_Type);
    result = PyObject_NEW(PydaProcess, &PydaProcess_Type);
    if (result != NULL)
        result->main_thread = t;
    
    result->main_thread->py_obj = (PyObject*)result;

    PyBuffer_Release(&bin_path);
    return (PyObject*)result;
}

static PyObject *
PydaProcess_run(PyObject* self, PyObject *noarg) {
    PydaProcess *p = (PydaProcess*)self;
    Py_BEGIN_ALLOW_THREADS
    pyda_yield(p->main_thread);
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

    const char *regname;

    if (!PyArg_ParseTuple(args, "s", &regname))
        return NULL;

#ifdef PYDA_DYNAMORIO_CLIENT
    // DEBUG_PRINTF("get_register: %s\n", regname);
    dr_mcontext_t *mc = &t->cur_context;

    // TODO: Fix... copilot wrote this. Surely we can write
    // a macro...
    if (strcmp(regname, "rax") == 0) {
        return PyLong_FromUnsignedLong((unsigned long)mc->rax);
    } else if (strcmp(regname, "rbx") == 0) {
        return PyLong_FromUnsignedLong((unsigned long)mc->rbx);
    } else if (strcmp(regname, "rcx") == 0) {
        return PyLong_FromUnsignedLong((unsigned long)mc->rcx);
    } else if (strcmp(regname, "rsp") == 0) {
        return PyLong_FromUnsignedLong((unsigned long)mc->rsp);
    } else if (strcmp(regname, "rbp") == 0) {
        return PyLong_FromUnsignedLong((unsigned long)mc->rbp);
    } else if (strcmp(regname, "rdi") == 0) {
        return PyLong_FromUnsignedLong((unsigned long)mc->rdi);
    } else if (strcmp(regname, "rsi") == 0) {
        return PyLong_FromUnsignedLong((unsigned long)mc->rsi);
    } else if (strcmp(regname, "r8") == 0) {
        return PyLong_FromUnsignedLong((unsigned long)mc->r8);
    } else if (strcmp(regname, "r9") == 0) {
        return PyLong_FromUnsignedLong((unsigned long)mc->r9);
    } else if (strcmp(regname, "r10") == 0) {
        return PyLong_FromUnsignedLong((unsigned long)mc->r10);
    } else if (strcmp(regname, "r11") == 0) {
        return PyLong_FromUnsignedLong((unsigned long)mc->r11);
    } else if (strcmp(regname, "r12") == 0) {
        return PyLong_FromUnsignedLong((unsigned long)mc->r12);
    } else if (strcmp(regname, "r13") == 0) {
        return PyLong_FromUnsignedLong((unsigned long)mc->r13);
    } else if (strcmp(regname, "r14") == 0) {
        return PyLong_FromUnsignedLong((unsigned long)mc->r14);
    } else if (strcmp(regname, "r15") == 0) {
        return PyLong_FromUnsignedLong((unsigned long)mc->r15);
    } else if (strcmp(regname, "rdx") == 0) {
        return PyLong_FromUnsignedLong((unsigned long)mc->rdx);
    } else if (strcmp(regname, "fsbase") == 0) {
        return PyLong_FromUnsignedLong((unsigned long)dr_get_tls_field(dr_get_current_drcontext()));
    } else if (strcmp(regname, "rip") == 0 || strcmp(regname, "pc") == 0) {
        return PyLong_FromUnsignedLong((unsigned long)mc->pc);
    } else if (strcmp(regname, "xmm0") == 0) {
        uint64_t val[2];
        reg_get_value_ex(DR_REG_XMM0, mc, (uint8_t*)&val);
        return PyLong_FromUnsignedLong(val[0]); // todo: we lose the top
    } else if (strcmp(regname, "xmm1") == 0) {
        uint64_t val[2];
        reg_get_value_ex(DR_REG_XMM1, mc, (uint8_t*)&val);
        return PyLong_FromUnsignedLong(val[0]); // todo: we lose the top
    } else if (strcmp(regname, "xmm2") == 0) {
        uint64_t val[2];
        reg_get_value_ex(DR_REG_XMM2, mc, (uint8_t*)&val);
        return PyLong_FromUnsignedLong(val[0]); // todo: we lose the top
    } else if (strcmp(regname, "xmm3") == 0) {
        uint64_t val[2];
        reg_get_value_ex(DR_REG_XMM3, mc, (uint8_t*)&val);
        return PyLong_FromUnsignedLong(val[0]); // todo: we lose the top
    }
#endif // PYDA_DYNAMORIO_CLIENT

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
PydaProcess_set_register(PyObject *self, PyObject *args) {
    PydaProcess *p = (PydaProcess*)self;
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);

    const char *regname;
    unsigned long long val;

    if (!PyArg_ParseTuple(args, "sK", &regname, &val))
        return NULL;


#ifdef PYDA_DYNAMORIO_CLIENT
    DEBUG_PRINTF("set_register: %s %llx\n", regname, val);
    // DEBUG_PRINTF("get_register: %s\n", regname);
    dr_mcontext_t *mc = &t->cur_context;

    // TODO: Fix... copilot wrote this. Surely we can write
    // a macro...
    if (strcmp(regname, "rax") == 0) {
        mc->rax = val;
    } else if (strcmp(regname, "rbx") == 0) {
        mc->rbx = val;
    } else if (strcmp(regname, "rcx") == 0) {
        mc->rcx = val;
    } else if (strcmp(regname, "rsp") == 0) {
        mc->rsp = val;
    } else if (strcmp(regname, "rbp") == 0) {
        mc->rbp = val;
    } else if (strcmp(regname, "rdi") == 0) {
        mc->rdi = val;
    } else if (strcmp(regname, "rsi") == 0) {
        mc->rsi = val;
    } else if (strcmp(regname, "r8") == 0) {
        mc->r8 = val;
    } else if (strcmp(regname, "r9") == 0) {
        mc->r9 = val;
    } else if (strcmp(regname, "r10") == 0) {
        mc->r10 = val;
    } else if (strcmp(regname, "r11") == 0) {
        mc->r11 = val;
    } else if (strcmp(regname, "r12") == 0) {
        mc->r12 = val;
    } else if (strcmp(regname, "r13") == 0) {
        mc->r13 = val;
    } else if (strcmp(regname, "r14") == 0) {
        mc->r14 = val;
    } else if (strcmp(regname, "r15") == 0) {
        mc->r15 = val;
    } else if (strcmp(regname, "rdx") == 0) {
        mc->rdx = val;
    } else if (strcmp(regname, "rip") == 0 || strcmp(regname, "pc") == 0) {
        mc->pc = (void*)val;
        t->rip_updated_in_cleancall = 1;
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
    Py_INCREF(callback);
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
#endif // PYDA_DYNAMORIO_CLIENT
    Py_INCREF(callback);
    pyda_set_thread_init_hook(p->main_thread->proc, callback);

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