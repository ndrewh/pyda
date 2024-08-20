#include "pyda_core.h"
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <sys/ucontext.h>

int pyda_get_backtrace (pyda_thread *t, char *buf, int size) {
  unw_cursor_t cursor; unw_context_t uc;
  unw_word_t ip, sp;

  unw_getcontext(&uc);
  ucontext_t *uc2 = (ucontext_t *) &uc;

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

  unw_init_local(&cursor, &uc);

  char *bufcur = buf;
  do {
    char sym[256];
    unw_word_t offset;

    unw_get_reg(&cursor, UNW_REG_IP, &ip);
    unw_get_reg(&cursor, UNW_REG_SP, &sp);

    module_data_t *mod = dr_lookup_module((void*)ip);
    int res;
    if (mod) {
        char *modname = strrchr(mod->full_path, '/');
        if (modname) {
            modname++;
        } else {
            modname = mod->full_path;
        }

        res = snprintf(bufcur, size, "[%s+0x%lx]\t", modname, (uint64_t)ip - (uint64_t)mod->start);
    } else {
        res = snprintf(bufcur, size, "\t");
    }

    if (res > 0 && res <= size) {
        bufcur += res;
        size -= res;
    }

    if (unw_get_proc_name(&cursor, sym, sizeof(sym), &offset) == 0) {
        res = snprintf(bufcur, size,"(%s+0x%lx)\tip = %lx, sp = %lx\n", sym, offset, (uint64_t) ip, (uint64_t) sp);
    } else {
        res = snprintf(bufcur, size, "\t\tip = %lx, sp = %lx\n", (uint64_t) ip, (uint64_t) sp);
    }

    if (res > 0 && res <= size) {
        bufcur += res;
        size -= res;
    }
  } while (unw_step(&cursor) > 0);

  return 0;
}