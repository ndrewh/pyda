#include "pyda_core_py.h"
#include "pyda_core.h"
#include "pyda_threads.h"
#include "pyda_util.h"

#ifdef PYDA_DYNAMORIO_CLIENT
#include "dr_api.h"
#endif

int is_dynamorio_running = 0;

typedef struct {
    PyObject_HEAD
    pyda_thread *main_thread; // main thread
} PydaProcess;

static PyObject* pyda_core_process(PyObject *self, PyObject *args, PyObject *kwargs);
static PyObject* pyda_core_free(PyObject *self, PyObject *args, PyObject *kwargs);
static PyObject *pyda_list_modules(PyObject *self, PyObject *noarg);
static PyObject *pyda_get_base(PyObject *self, PyObject *args);
static PyObject *pyda_get_module_for_addr(PyObject *self, PyObject *args);
static PyObject *pyda_get_current_thread_id(PyObject *self, PyObject *noarg);
static PyObject *pyda_core_expr(PyObject *self, PyObject *args, PyObject *kwargs);
static PyObject *pyda_core_expr_raw(PyObject *self, PyObject *args, PyObject *kwargs);
static PyObject *pyda_core_free_expr(PyObject *self, PyObject *args, PyObject *kwargs);

static void PydaProcess_dealloc(PydaProcess *self);
static PyObject *PydaProcess_run(PyObject *self, PyObject *noarg);
static PyObject *PydaProcess_run_until_io(PyObject *self, PyObject *noarg);
static PyObject *PydaProcess_run_until_pc(PyObject *self, PyObject *arg);
static PyObject *PydaProcess_exited(PyObject *self, PyObject *noarg);
static PyObject *PydaProcess_capture_io(PyObject *self, PyObject *noarg);
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
static PyObject *PydaProcess_set_module_load_hook(PyObject *self, PyObject *args);
static PyObject *PydaProcess_push_state(PyObject *self, PyObject *args);
static PyObject *PydaProcess_pop_state(PyObject *self, PyObject *args);
static PyObject *PydaProcess_backtrace(PyObject *self, PyObject *noarg);

static void PydaExprBuilder_dealloc(PydaExprBuilder *self);
static PyObject *PydaExprBuilder_get_register(PyObject *self, PyObject *args);
static PyObject *PydaExprBuilder_set_register(PyObject *self, PyObject *args);


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
    {"free",  (PyCFunction)pyda_core_free, METH_KEYWORDS | METH_VARARGS,
     "Call into the allocator used by the rest of the tool."},
    {"expr",  (PyCFunction)pyda_core_expr, METH_KEYWORDS | METH_VARARGS,
     "Create a new expression. May be abstract (e.g. representing a register value) or concrete (e.g. representing an integer constant)."},
    {"expr_raw",  (PyCFunction)pyda_core_expr_raw, METH_KEYWORDS | METH_VARARGS,
     "Create a new raw (assembly) expression."},
    {"free_expr",  (PyCFunction)pyda_core_free_expr, METH_KEYWORDS | METH_VARARGS,
     "Free an expression and its children if refcount reaches 0."},
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
static PyObject *ThreadExitError;
static PyObject *InvalidStateError;
static PyObject *FatalSignalError;

static PyMethodDef PydaExprBuilder_methods[] = {
    {"get_register", (PyCFunction)PydaExprBuilder_get_register, METH_VARARGS,
     "Get a register value"},
    {"set_register", (PyCFunction)PydaExprBuilder_set_register, METH_VARARGS,
     "Set a register to an expression"},
    {NULL}  /* Sentinel */
};

PyTypeObject PydaExprBuilder_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pyda_core.ExprBuilder",
    .tp_doc = "Expression Builder object",
    .tp_basicsize = sizeof(PydaExprBuilder),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyType_GenericNew,
    .tp_dealloc = (destructor)PydaExprBuilder_dealloc,
    .tp_methods = PydaExprBuilder_methods,
};

static PyMethodDef PydaProcessMethods[] = {
    {"run",  PydaProcess_run, METH_NOARGS, "Run"},
    {"run_until_pc",  PydaProcess_run_until_pc, METH_VARARGS, "Run until PC is reached"},
    {"run_until_io",  PydaProcess_run_until_io, METH_NOARGS, "Run until IO syscall"},
    {"capture_io", PydaProcess_capture_io, METH_NOARGS, "Capture IO -- returns IO fds"},
    {"register_hook",  PydaProcess_register_hook, METH_VARARGS, "Register a hook"},
    {"unregister_hook",  PydaProcess_unregister_hook, METH_VARARGS, "Un-register a hook"},
    {"set_thread_init_hook",  PydaProcess_set_thread_init_hook, METH_VARARGS, "Register thread init hook"},
    {"get_register",  PydaProcess_get_register, METH_VARARGS, "Get a specific register"},
    {"set_register",  PydaProcess_set_register, METH_VARARGS, "Set a specific register"},
    {"get_main_module",  PydaProcess_get_main_module, METH_VARARGS, "Get name of main module"},
    {"read",  PydaProcess_read, METH_VARARGS, "Read memory"},
    {"write",  PydaProcess_write, METH_VARARGS, "Write memory"},
    {"exited",  PydaProcess_exited, METH_NOARGS, "Check if thread has exited"},
    // {"set_syscall_filter",  PydaProcess_set_syscall_filter, METH_VARARGS, "Set list of syscalls to call hooks on"},
    {"set_syscall_pre_hook",  PydaProcess_set_syscall_pre_hook, METH_VARARGS, "Register syscall pre hook"},
    {"set_syscall_post_hook",  PydaProcess_set_syscall_post_hook, METH_VARARGS, "Register syscall post hook"},
    {"set_module_load_hook",  PydaProcess_set_module_load_hook, METH_VARARGS, "Register module load hook"},
    {"push_state",  PydaProcess_push_state, METH_VARARGS, "Push register state (thread-local)"},
    {"pop_state",  PydaProcess_pop_state, METH_VARARGS, "Pop register state (thread-local)"},
    {"backtrace", PydaProcess_backtrace, METH_NOARGS, "Returns backtrace (array of tuples)"},
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

static void register_exception(PyObject *mod, PyObject **target, const char *fullname, const char *name) {
    *target = PyErr_NewException(fullname, NULL, NULL);
    Py_XINCREF(*target);
    if (PyModule_AddObject(mod, name, *target) < 0) {
        Py_XDECREF(*target);
        Py_CLEAR(*target);
    }
}

PyMODINIT_FUNC
PyInit_pyda_core(void) {
    PyObject *m = PyModule_Create(&pyda_module);

    register_exception(m, &MemoryError, "pyda.MemoryError", "MemoryError");
    register_exception(m, &ThreadExitError, "pyda.ThreadExitError", "ThreadExitError");
    register_exception(m, &InvalidStateError, "pyda.InvalidStateError", "InvalidStateError");
    register_exception(m, &FatalSignalError, "pyda.FatalSignalError", "FatalSignalError");

#if defined(X86)
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
    PyModule_AddIntConstant(m, "REG_PC", PYDA_REG_PC); // alias
    PyModule_AddIntConstant(m, "REG_SP", DR_REG_RSP); // alias
    PyModule_AddIntConstant(m, "REG_FSBASE", PYDA_REG_FSBASE);
    PyModule_AddIntConstant(m, "REG_XMM0", DR_REG_XMM0);
    PyModule_AddIntConstant(m, "REG_XMM1", DR_REG_XMM1);
    PyModule_AddIntConstant(m, "REG_XMM2", DR_REG_XMM2);
    PyModule_AddIntConstant(m, "REG_XMM3", DR_REG_XMM3);
    PyModule_AddIntConstant(m, "REG_XMM4", DR_REG_XMM4);
    PyModule_AddIntConstant(m, "REG_XMM5", DR_REG_XMM5);
    PyModule_AddIntConstant(m, "REG_XMM6", DR_REG_XMM6);
    PyModule_AddIntConstant(m, "REG_XMM7", DR_REG_XMM7);
    PyModule_AddIntConstant(m, "REG_ARG1", DR_REG_RDI);
    PyModule_AddIntConstant(m, "REG_ARG2", DR_REG_RSI);
    PyModule_AddIntConstant(m, "REG_ARG3", DR_REG_RDX);
    PyModule_AddIntConstant(m, "REG_ARG4", DR_REG_RCX);
    PyModule_AddIntConstant(m, "REG_ARG5", DR_REG_R8);
    PyModule_AddIntConstant(m, "REG_ARG6", DR_REG_R9);
#elif defined(AARCH64)
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
    PyModule_AddIntConstant(m, "REG_SP", DR_REG_SP); // alias
    PyModule_AddIntConstant(m, "REG_PC", PYDA_REG_PC);
    PyModule_AddIntConstant(m, "REG_ARG1", DR_REG_R0);
    PyModule_AddIntConstant(m, "REG_ARG2", DR_REG_R1);
    PyModule_AddIntConstant(m, "REG_ARG3", DR_REG_R2);
    PyModule_AddIntConstant(m, "REG_ARG4", DR_REG_R3);
    PyModule_AddIntConstant(m, "REG_ARG5", DR_REG_R4);
    PyModule_AddIntConstant(m, "REG_ARG6", DR_REG_R5);
#endif

    // Add expression type constants
    PyModule_AddIntConstant(m, "EXPR_TYPE_CONST", EXPR_TYPE_CONST);
    PyModule_AddIntConstant(m, "EXPR_TYPE_ADD", EXPR_TYPE_ADD);
    PyModule_AddIntConstant(m, "EXPR_TYPE_SUB", EXPR_TYPE_SUB);
    PyModule_AddIntConstant(m, "EXPR_TYPE_MUL", EXPR_TYPE_MUL);
    PyModule_AddIntConstant(m, "EXPR_TYPE_DIV", EXPR_TYPE_DIV);
    PyModule_AddIntConstant(m, "EXPR_TYPE_LOAD", EXPR_TYPE_LOAD);
    PyModule_AddIntConstant(m, "EXPR_TYPE_STORE", EXPR_TYPE_STORE);

    // Initialize ExprBuilder type
    if (PyType_Ready(&PydaExprBuilder_Type) < 0)
        return NULL;

    if (PyType_Ready(&PydaProcess_Type) < 0)
        return NULL;

    return m;
}

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

    result = PyObject_NEW(PydaProcess, &PydaProcess_Type);
    if (result != NULL)
        result->main_thread = t;

    t->proc->py_obj = (PyObject*)result;

    PyBuffer_Release(&bin_path);
    return (PyObject*)result;
}

/* This is a hack (note this calls the private allocator, separate from the one used by the app running under Dyanmorio) */
static PyObject *
pyda_core_free(PyObject *self, PyObject *args, PyObject *kwargs) {
    unsigned long addr;
    if (!PyArg_ParseTuple(args, "K", &addr))
        return NULL;

    free((void*)addr);

    Py_INCREF(Py_None);
    return Py_None;
}
static int check_valid_thread(pyda_thread *t) {
    if (!t) {
        PyErr_SetString(PyExc_RuntimeError, "Threads created with Python threading APIs cannot use Pyda APIs");
        return 1;
    }
    return 0;
}

static int check_python_thread(pyda_thread *t) {
    if (pyda_thread_getspecific(g_pyda_tls_is_python_thread_idx) != (void*)1) {
        PyErr_SetString(InvalidStateError, ".run()/.run_until() cannot be called from hooks.");
        return 1;
    }
    return 0;
}

static int check_exited(pyda_thread *t) {
    if (check_valid_thread(t)) return 1;
    if (t->app_exited) {
        PyErr_SetString(InvalidStateError, "Thread has already exited; cannot be resumed");
        return 1;
    }
    return 0;
}
static int check_signal(pyda_thread *t) {
    if (t->signal) {
        PyObject *tuple = PyTuple_New(3);
        PyTuple_SetItem(tuple, 0, PyLong_FromLong(t->signal));
        PyTuple_SetItem(tuple, 1, PyLong_FromLong(t->tid));
        PyTuple_SetItem(tuple, 2, PydaProcess_backtrace(NULL, NULL));
        PyErr_SetObject(FatalSignalError, tuple);
        return 1;
    }
    return 0;
}


static PyObject *
PydaProcess_run(PyObject* self, PyObject *noarg) {
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (check_python_thread(t)) return NULL;
    if (check_exited(t)) return NULL;

    Py_BEGIN_ALLOW_THREADS
    pyda_yield(t);
#ifdef PYDA_DYNAMORIO_CLIENT
    DEBUG_PRINTF("yield returned\n");
#endif // PYDA_DYNAMORIO_CLIENT
    Py_END_ALLOW_THREADS

    if (check_signal(t)) return NULL;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
PydaProcess_run_until_io(PyObject* self, PyObject *noarg) {
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (check_python_thread(t)) return NULL;
    if (check_exited(t)) return NULL;

    t->python_blocked_on_io = 1;


    // todo: assert that this thread is like, actually blocked

    Py_BEGIN_ALLOW_THREADS
    pyda_yield(t);
#ifdef PYDA_DYNAMORIO_CLIENT
    DEBUG_PRINTF("yield after io returned\n");
#endif // PYDA_DYNAMORIO_CLIENT
    Py_END_ALLOW_THREADS

    if (t->app_exited) {
        PyErr_SetString(ThreadExitError, "Thread exited while Pyda was waiting on I/O.");
        return NULL;
    }

    if (check_signal(t)) return NULL;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
PydaProcess_capture_io(PyObject* self, PyObject *noarg) {
    PydaProcess *p = (PydaProcess*)self;
    pyda_process *proc = p->main_thread->proc;

    if (!getenv("PYDA_NO_CAPTURE") || getenv("PYDA_NO_CAPTURE")[0] != '1') {
        int no_pty = (getenv("PYDA_NO_PTY") && getenv("PYDA_NO_PTY")[0] == '1');
        int no_raw = (getenv("PYDA_NO_RAW") && getenv("PYDA_NO_RAW")[0] == '1');
        pyda_capture_io(proc, !no_pty, !no_raw);
    }

    if (proc->stdin_fd == -1) {
        PyErr_SetString(PyExc_RuntimeError, "IO was not captured");
        return NULL;
    }

    PyObject *list = PyList_New(0);
    PyList_Append(list, PyLong_FromLong(proc->stdin_fd));
    PyList_Append(list, PyLong_FromLong(proc->stdout_fd));
    PyList_Append(list, PyLong_FromLong(proc->stderr_fd));

    return list;
}

static PyObject *
PydaProcess_backtrace(PyObject* self, PyObject *noarg) {
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (check_exited(t)) return NULL;

    drvector_t backtrace;

    int ret = pyda_get_backtrace(t, &backtrace);

    PyObject *list = PyList_New(0);
    for (int i=0; i<backtrace.entries; i++) {
        struct pyda_bt_entry *e = backtrace.array[i];

        PyObject *tuple = PyTuple_New(4);
        PyTuple_SetItem(tuple, 0, PyLong_FromLong(e->ip));
        PyTuple_SetItem(tuple, 1, PyUnicode_FromString(e->modname));
        PyTuple_SetItem(tuple, 2, PyLong_FromLong(e->offset));
        PyTuple_SetItem(tuple, 3, PyUnicode_FromString(e->sym_name));
        PyList_Append(list, tuple);
    }

    drvector_delete(&backtrace);

    if (ret) {
        Py_DECREF(list);
        PyErr_SetString(PyExc_RuntimeError, "Could not generate backtrace");
        return NULL;
    }

    return list;
}

static PyObject *
PydaProcess_run_until_pc(PyObject* self, PyObject *args) {
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (check_python_thread(t)) return NULL;
    if (check_exited(t)) return NULL;

    unsigned long addr;
    if (!PyArg_ParseTuple(args, "K", &addr))
        return NULL;

    pyda_set_run_until(t, (void*)addr);

    Py_BEGIN_ALLOW_THREADS
    pyda_yield(t);
#ifdef PYDA_DYNAMORIO_CLIENT
    DEBUG_PRINTF("yield returned\n");
#endif // PYDA_DYNAMORIO_CLIENT
    Py_END_ALLOW_THREADS

    if (t->app_exited) {
        PyErr_SetString(ThreadExitError, "Thread exited before reaching run_until target.");
        return NULL;
    }

    if (check_signal(t)) return NULL;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
PydaProcess_exited(PyObject* self, PyObject *noarg) {
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (check_valid_thread(t)) return NULL;
    if (t->app_exited) {
        Py_INCREF(Py_True);
        return Py_True;
    }
    Py_INCREF(Py_False);
    return Py_False;
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
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (check_valid_thread(t)) return NULL;
    int tid = t->tid;
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
    if (check_exited(t)) return NULL;

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
    if (snprintf(buf, sizeof(buf), "0x%" PRIx64 "%" PRIx64, val[1], val[0]) >= sizeof(buf)) {
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
    if (check_exited(t)) return NULL;

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
        t->rip_updated_in_python = 1;
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
    unsigned long long callback_type;
    bool later;

    if (!PyArg_ParseTuple(args, "KO!Kb", &addr, &PyFunction_Type, &callback, &callback_type, &later))
        return NULL;

    PyCodeObject *code = (PyCodeObject*)PyFunction_GetCode(callback);
    if (!code || code->co_argcount != 1) {
        PyErr_SetString(PyExc_RuntimeError, "Callback must take one argument");
        return NULL;
    }

#ifdef PYDA_DYNAMORIO_CLIENT
    DEBUG_PRINTF("register_hook: %llx\n", addr);

    int readable = dr_memory_is_readable((app_pc)addr, 1);
    if (!later && !readable) {
        char buf[100];
        snprintf(buf, sizeof(buf), "Hooked PC %" PRIxPTR " is invalid; try later=True if this will be mapped later.", (uintptr_t)addr);
        PyErr_SetString(PyExc_RuntimeError, buf);
        return NULL;
    }

    // 0 is a regular hook, 1 is a advanced "builder" hook
    if (callback_type != 0 && callback_type != 1) {
        PyErr_SetString(PyExc_RuntimeError, "Invalid callback type");
        return NULL;
    }

    pyda_add_hook(p->main_thread->proc, addr, callback, callback_type, readable);

#endif // PYDA_DYNAMORIO_CLIENT
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
PydaProcess_set_module_load_hook(PyObject *self, PyObject *args) {
    PydaProcess *p = (PydaProcess*)self;

    PyObject *callback;

    if (!PyArg_ParseTuple(args, "O!", &PyFunction_Type, &callback))
        return NULL;

    PyCodeObject *code = (PyCodeObject*)PyFunction_GetCode(callback);
    if (!code || code->co_argcount != 2) {
        PyErr_SetString(PyExc_RuntimeError, "Callback must take two arguments (process, module_path)");
        return NULL;
    }

#ifdef PYDA_DYNAMORIO_CLIENT
    DEBUG_PRINTF("set_module_load_hook\n");
#endif

    // note: pyda_set_module_load_hook calls incref
    pyda_set_module_load_hook(p->main_thread->proc, callback);

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

static PyObject *
PydaProcess_push_state(PyObject* self, PyObject *noarg) {
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (check_exited(t)) return NULL;

    // NOTE: Before we entered python, we saved the state (see: calls to dr_get_mcontext)
    if (!pyda_push_context(t)) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to push state");
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
PydaProcess_pop_state(PyObject* self, PyObject *noarg) {
    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (check_exited(t)) return NULL;

    if (!pyda_pop_context(t)) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to pop state");
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
pyda_core_expr(PyObject *self, PyObject *args, PyObject *kwargs) {
    unsigned long expr_type, op1, op2;
    if (!PyArg_ParseTuple(args, "KKK", &expr_type, &op1, &op2))
        return NULL;

    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (check_valid_thread(t)) return NULL;

    if (t->expr_builder == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Expression builder not initialized");
        return NULL;
    }

    unsigned long handle = expr_new(t->expr_builder, expr_type, op1, op2);
    if (handle == (unsigned long)-1) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to create expression");
        return NULL;
    }

    return PyLong_FromUnsignedLong(handle);
}


static PyObject *
pyda_core_expr_raw(PyObject *self, PyObject *args, PyObject *kwargs) {
    const char *data;
    Py_ssize_t len;
    if (!PyArg_ParseTuple(args, "s#", &data, &len))
        return NULL;

    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (check_valid_thread(t)) return NULL;

    if (t->expr_builder == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Expression builder not initialized");
        return NULL;
    }

    unsigned long handle = expr_new_raw(t->expr_builder, data, len);
    if (handle == (unsigned long)-1) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to create raw expression");
        return NULL;
    }

    return PyLong_FromUnsignedLong(handle);
}

static PyObject *
pyda_core_free_expr(PyObject *self, PyObject *args, PyObject *kwargs) {
    unsigned long handle;
    if (!PyArg_ParseTuple(args, "K", &handle))
        return NULL;

    pyda_thread *t = pyda_thread_getspecific(g_pyda_tls_idx);
    if (check_valid_thread(t)) return NULL;

    if (t->expr_builder == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "Expression builder not initialized");
        return NULL;
    }

    expr_free(t->expr_builder, handle);

    Py_INCREF(Py_None);
    return Py_None;
}

static void
PydaExprBuilder_dealloc(PydaExprBuilder *self) {
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
PydaExprBuilder_get_register(PyObject *self, PyObject *args) {
    PydaExprBuilder *builder = (PydaExprBuilder*)self;
    unsigned long reg_id;
    if (!PyArg_ParseTuple(args, "K", &reg_id))
        return NULL;

    unsigned long handle;
    if (!exprbuilder_reg_get(builder->builder, reg_id, &handle)) {
        handle = expr_new(builder->builder, EXPR_TYPE_REG, reg_id, 0);
        if (handle == (unsigned long)-1 || !exprbuilder_reg_set(builder->builder, reg_id, handle)) {
            PyErr_SetString(PyExc_RuntimeError, "Failed to get register value");
            return NULL;
        }
    } else {
        exprbuilder_incref(builder->builder, handle);
    }

    return PyLong_FromUnsignedLong(handle);
}

static PyObject *
PydaExprBuilder_set_register(PyObject *self, PyObject *args) {
    PydaExprBuilder *builder = (PydaExprBuilder*)self;
    unsigned long reg_id;
    unsigned long handle;
    if (!PyArg_ParseTuple(args, "KK", &reg_id, &handle))
        return NULL;

    if (!exprbuilder_reg_set(builder->builder, reg_id, handle)) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to set register value");
        return NULL;
    }

    Py_RETURN_NONE;
}
