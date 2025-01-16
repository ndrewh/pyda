#ifndef PYDA_COMPILER_H
#define PYDA_COMPILER_H

#include <dr_api.h>
#include "hashtable.h"
#include "drvector.h"
#include <Python.h>

struct Expr {
    unsigned long ty;
    unsigned long op1;
    unsigned long op2;
    int refcount;
};

struct ExprRaw {
    struct Expr base;
    instrlist_t *code;
};

// Expression types
#define EXPR_TYPE_CONST  1
#define EXPR_TYPE_ADD    2
#define EXPR_TYPE_SUB    3
#define EXPR_TYPE_MUL    4
#define EXPR_TYPE_DIV    5
#define EXPR_TYPE_LOAD   6
#define EXPR_TYPE_STORE  7
#define EXPR_TYPE_REG    8
#define EXPR_TYPE_RAW    9

/* a per-thread structure that tracks Expr lifetimes and provides (mutable) access
 * to an abstract register state.
 */
struct ExprBuilder {
    drvector_t exprs; /* Exprs that are live in this thread */
    dr_mcontext_t mc; /* register values (handles to Exprs) */
    drvector_t ops; /* loads, stores, raw insns which must be retained regardless */
};

typedef struct ExprBuilder ExprBuilder;

// Function declarations
ExprBuilder *exprbuilder_init();
void exprbuilder_delete(ExprBuilder *builder);
unsigned long expr_new(ExprBuilder *builder, unsigned long ty, unsigned long op1, unsigned long op2);
unsigned long expr_new_raw(ExprBuilder *builder, const char *buf, size_t size);
void expr_free(ExprBuilder *builder, unsigned long handle);
int exprbuilder_reg_get(ExprBuilder *builder, reg_id_t reg_id, unsigned long *handle);
int exprbuilder_reg_set(ExprBuilder *builder, reg_id_t reg_id, unsigned long handle);
int exprbuilder_compile(ExprBuilder *builder, instrlist_t *bb, instr_t *instr, int expr_handle_start);
void exprbuilder_incref(ExprBuilder *builder, unsigned long handle);



#endif // PYDA_COMPILER_H