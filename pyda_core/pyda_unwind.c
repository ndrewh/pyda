#include "pyda_core.h"
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <sys/ucontext.h>

static void free_bt_entry(void *ptr) {
    dr_global_free(ptr, sizeof(struct pyda_bt_entry));
}

int pyda_get_backtrace (pyda_thread *t, drvector_t *res) {
  unw_cursor_t cursor; unw_context_t uc;
  unw_word_t ip, sp;

  unw_getcontext(&uc);
  ucontext_t *uc2 = (ucontext_t *) &uc;

#if defined(LINUX)
#if defined(__x86_64__)
  uc2->uc_mcontext.gregs[REG_RIP] = (uintptr_t)t->cur_context.pc;
  uc2->uc_mcontext.gregs[REG_RSP] = t->cur_context.rsp;
  uc2->uc_mcontext.gregs[REG_RBP] = t->cur_context.rbp;
  uc2->uc_mcontext.gregs[REG_RDI] = t->cur_context.rdi;
  uc2->uc_mcontext.gregs[REG_RSI] = t->cur_context.rsi;
  uc2->uc_mcontext.gregs[REG_RDX] = t->cur_context.rdx;
  uc2->uc_mcontext.gregs[REG_RCX] = t->cur_context.rcx;
  uc2->uc_mcontext.gregs[REG_R8] = t->cur_context.r8;
  uc2->uc_mcontext.gregs[REG_R9] = t->cur_context.r8;
#elif defined(AARCH64)
  uc2->uc_mcontext.pc = (uintptr_t)t->cur_context.pc;
  uc2->uc_mcontext.regs[0] = t->cur_context.r0;
  uc2->uc_mcontext.regs[1] = t->cur_context.r1;
  uc2->uc_mcontext.regs[2] = t->cur_context.r2;
  uc2->uc_mcontext.regs[3] = t->cur_context.r3;
  uc2->uc_mcontext.regs[4] = t->cur_context.r4;
  uc2->uc_mcontext.regs[5] = t->cur_context.r5;
  uc2->uc_mcontext.regs[6] = t->cur_context.r6;
  uc2->uc_mcontext.regs[7] = t->cur_context.r7;
  uc2->uc_mcontext.sp = t->cur_context.sp;
  uc2->uc_mcontext.regs[30] = t->cur_context.lr;
#else
#error "Unsupported architecture"
#endif

#elif defined(MACOS) /* continuation of defined(LINUX) */
#if defined(__x86_64__)
  uc2->uc_mcontext->__ss.__rip = (uintptr_t)t->cur_context.pc;
  uc2->uc_mcontext->__ss.__rsp = t->cur_context.rsp;
  uc2->uc_mcontext->__ss.__rbp = t->cur_context.rbp;
  uc2->uc_mcontext->__ss.__rdi = t->cur_context.rdi;
  uc2->uc_mcontext->__ss.__rsi = t->cur_context.rsi;
  uc2->uc_mcontext->__ss.__rdx = t->cur_context.rdx;
  uc2->uc_mcontext->__ss.__rcx = t->cur_context.rcx;
  uc2->uc_mcontext->__ss.__r8 = t->cur_context.r8;
  uc2->uc_mcontext->__ss.__r9 = t->cur_context.r8;
#elif defined(AARCH64)
  uc2->uc_mcontext->__ss.__pc = (uintptr_t)t->cur_context.pc;
  uc2->uc_mcontext->__ss.__x[0] = t->cur_context.r0;
  uc2->uc_mcontext->__ss.__x[1] = t->cur_context.r1;
  uc2->uc_mcontext->__ss.__x[2] = t->cur_context.r2;
  uc2->uc_mcontext->__ss.__x[3] = t->cur_context.r3;
  uc2->uc_mcontext->__ss.__x[4] = t->cur_context.r4;
  uc2->uc_mcontext->__ss.__x[5] = t->cur_context.r5;
  uc2->uc_mcontext->__ss.__x[6] = t->cur_context.r6;
  uc2->uc_mcontext->__ss.__x[7] = t->cur_context.r7;
  uc2->uc_mcontext->__ss.__sp = t->cur_context.sp;
  uc2->uc_mcontext->__ss.__lr = t->cur_context.lr;
#else
#error "Unsupported architecture"
#endif

#endif /* end of defined(MACOS) */

  unw_init_local(&cursor, &uc);

  drvector_init(res, 0, true, free_bt_entry);

  do {
    struct pyda_bt_entry *e = dr_global_alloc(sizeof(struct pyda_bt_entry));

    char sym[512];
    unw_word_t offset;

    unw_get_reg(&cursor, UNW_REG_IP, &ip);
    unw_get_reg(&cursor, UNW_REG_SP, &sp);

    module_data_t *mod = dr_lookup_module((void*)ip);

    if (mod) {
        char *modname = strrchr(mod->full_path, '/');
        if (modname) {
            modname++;
        } else {
            modname = mod->full_path;
        }

        snprintf(e->modname, sizeof(e->modname), "%s", modname);
        e->offset = (uint64_t)ip - (uint64_t)mod->start;
    } else {
        e->modname[0] = 0;
        e->offset = 0;
    }

    if (unw_get_proc_name(&cursor, sym, sizeof(sym), &offset) == 0) {
        snprintf(e->sym_name, sizeof(e->sym_name), "%s", sym);
    } else {
        e->sym_name[0] = 0;
    }

    e->ip = ip;
    e->sp = sp;

    drvector_append(res, e);
  } while (unw_step(&cursor) > 0);

  return 0;
}

