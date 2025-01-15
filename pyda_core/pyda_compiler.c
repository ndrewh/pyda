#include <stdlib.h>
#include "pyda_compiler.h"
#include "pyda_core.h"
#include "drreg.h"
#include <stddef.h>

static int validate_and_increment_refs(ExprBuilder *builder, unsigned long ty, unsigned long op1, unsigned long op2) {
    switch (ty) {
        case EXPR_TYPE_ADD:
        case EXPR_TYPE_SUB:
        case EXPR_TYPE_MUL:
        case EXPR_TYPE_DIV:
        case EXPR_TYPE_STORE:
            if (op2 >= builder->exprs.entries || !builder->exprs.array[op2]) {
                return -1;
            }
            ((struct Expr *)builder->exprs.array[op2])->refcount++;
            // fall through
        case EXPR_TYPE_LOAD:
            if (op1 >= builder->exprs.entries || !builder->exprs.array[op1]) {
                return -1;
            }
            ((struct Expr *)builder->exprs.array[op1])->refcount++;
            break;
        case EXPR_TYPE_CONST:
        case EXPR_TYPE_REG:
            // Constants don't have child expressions
            break;
        default:
            dr_fprintf(STDERR, "unimplemented validate_and_increment_refs ty %d\n", ty);
            return -1;
    }
    return 0;
}

unsigned long expr_new(ExprBuilder *builder, unsigned long ty, unsigned long op1, unsigned long op2) {
    void *drcontext = dr_get_current_drcontext();
    struct Expr *expr = dr_thread_alloc(drcontext, sizeof(struct Expr));
    if (!expr) {
        return (unsigned long)-1;
    }

    if (validate_and_increment_refs(builder, ty, op1, op2) < 0) {
        dr_thread_free(drcontext, expr, sizeof(struct Expr));
        return (unsigned long)-1;
    }

    expr->ty = ty;
    expr->op1 = op1;
    expr->op2 = op2;
    expr->refcount = 1;

    // Add to builder's vector and return the index as handle
    unsigned int idx = builder->exprs.entries;
    drvector_append(&builder->exprs, expr);

    return idx;
}

void expr_free(ExprBuilder *builder, unsigned long handle) {
    void *drcontext = dr_get_current_drcontext();
    if (handle >= builder->exprs.entries) return;
    
    struct Expr *expr = builder->exprs.array[handle];
    if (!expr) {
        dr_fprintf(STDERR, "expr_free: invalid handle %lu\n", handle);
        return;
    }
    
    expr->refcount--;
    if (expr->refcount > 0) return;

    // Recursively free operands based on expression type
    switch (expr->ty) {
        case EXPR_TYPE_ADD:
        case EXPR_TYPE_SUB:
        case EXPR_TYPE_MUL:
        case EXPR_TYPE_DIV:
        case EXPR_TYPE_STORE:
            expr_free(builder, expr->op2);
            // fall through
        case EXPR_TYPE_LOAD:
            expr_free(builder, expr->op1);
            break;
        case EXPR_TYPE_CONST:
        case EXPR_TYPE_REG:
            // Constants don't have child expressions to free
            break;
        default:
            dr_fprintf(STDERR, "expr_free: invalid expression type %lu\n", expr->ty);
            break;
    }

    dr_thread_free(drcontext, expr, sizeof(struct Expr));
    builder->exprs.array[handle] = NULL;
}

ExprBuilder *exprbuilder_init() {
    ExprBuilder *builder = dr_thread_alloc(dr_get_current_drcontext(), sizeof(ExprBuilder));
    if (!builder) {
        dr_fprintf(STDERR, "Failed to allocate ExprBuilder\n");
        return NULL;
    }
    drvector_init(&builder->exprs, 0, true, NULL);
    memset(&builder->mc, 0xff, sizeof(dr_mcontext_t));
    builder->mc.size = sizeof(dr_mcontext_t);
    builder->mc.flags = DR_MC_ALL;
    return builder;
}

void exprbuilder_delete(ExprBuilder *builder) {
    // Check for leaked expressions
    for (uint i = 0; i < builder->exprs.entries; i++) {
        struct Expr *expr = builder->exprs.array[i];
        if (expr) {
            dr_fprintf(STDERR, "Warning: expression %u leaked (refcount: %d)\n", i, expr->refcount);
            expr_free(builder, i);
        }
    }

    drvector_delete(&builder->exprs);
}

int exprbuilder_reg_get(ExprBuilder *builder, reg_id_t reg_id, unsigned long *handle) {
    reg_t idx;
    reg_get_value_ex(reg_id, &builder->mc, (uint8_t*)&idx);

    // Validate that the stored index points to a valid expression
    if (idx >= builder->exprs.entries || !builder->exprs.array[idx]) {
        return 0;
    }

    *handle = (unsigned long)idx;
    return 1;
}

void exprbuilder_incref(ExprBuilder *builder, unsigned long handle) {
    // note: unchecked
    struct Expr *expr = builder->exprs.array[handle];
    expr->refcount++;
}

int exprbuilder_reg_set(ExprBuilder *builder, reg_id_t reg_id, unsigned long handle) {
    // Validate that we're setting a valid expression handle
    if (handle >= builder->exprs.entries || !builder->exprs.array[handle]) {
        return 0;
    }

    // Decref on the old handle, if applicable
    reg_t old_handle;
    reg_get_value_ex(reg_id, &builder->mc, (uint8_t*)&old_handle);
    if (old_handle < builder->exprs.entries && builder->exprs.array[handle]) {
        expr_free(builder, (unsigned long)old_handle);
    }

    reg_t new_handle = handle;
    reg_set_value_ex(reg_id, &builder->mc, (uint8_t*)&new_handle);
    exprbuilder_incref(builder, handle);
    return 1;
}

extern int g_pyda_tls_idx;

int exprbuilder_compile(ExprBuilder *builder, instrlist_t *bb, instr_t *instr) {
    void *drcontext = dr_get_current_drcontext();
    instr_t *new_instr;
    reg_id_t reg, scratch_reg;
    reg_id_t op1_reg, op2_reg;

    if (builder->exprs.entries > SCRATCH_SLOTS) {
        dr_fprintf(STDERR, "Register allocation is not yet implemented");
        return 0;
    }

    // Reserve a register for accessing TLS
    if (drreg_reserve_register(drcontext, bb, instr, NULL, &scratch_reg) != DRREG_SUCCESS) {
        dr_fprintf(STDERR, "Failed to reserve scratch register\n");
        return 0;
    }

    // Reserve registers for operands
    if (drreg_reserve_register(drcontext, bb, instr, NULL, &op1_reg) != DRREG_SUCCESS) {
        dr_fprintf(STDERR, "Failed to reserve op1 register\n");
        return 0;
    }

    if (drreg_reserve_register(drcontext, bb, instr, NULL, &op2_reg) != DRREG_SUCCESS) {
        dr_fprintf(STDERR, "Failed to reserve op2 register\n");
        return 0;
    }

    if (!drmgr_insert_read_tls_field(drcontext, g_pyda_tls_idx, bb, instr, scratch_reg)) {
        dr_fprintf(STDERR, "Failed to read TLS field\n");
        return 0;
    }

    opnd_t scratch_base = opnd_create_reg(scratch_reg);

    // Add offsetof(pyda_thread, scratch_region) to the base address
    new_instr = XINST_CREATE_add(drcontext, scratch_base, opnd_create_immed_int(offsetof(pyda_thread, scratch_region), OPSZ_8));
    instrlist_meta_preinsert(bb, instr, new_instr);

    // Use the scratch region for each expression
    for (unsigned long i = 0; i < builder->exprs.entries; i++) {
        struct Expr *expr = builder->exprs.array[i];
        if (!expr) continue;

        if (expr->ty != EXPR_TYPE_CONST && expr->ty != EXPR_TYPE_REG) {
            new_instr = XINST_CREATE_load(drcontext, opnd_create_reg(op1_reg), opnd_create_base_disp(scratch_reg, DR_REG_NULL, 0, 8 * expr->op1, OPSZ_8));
            instrlist_meta_preinsert(bb, instr, new_instr);
        }

        if (expr->ty != EXPR_TYPE_CONST && expr->ty != EXPR_TYPE_REG && expr->ty != EXPR_TYPE_LOAD) {
            new_instr = XINST_CREATE_load(drcontext, opnd_create_reg(op2_reg), opnd_create_base_disp(scratch_reg, DR_REG_NULL, 0, 8 * expr->op2, OPSZ_8));
            instrlist_meta_preinsert(bb, instr, new_instr);
        }

        // Compute the expression and store the result in the scratch region
        // XXX: We should check that none of these touch flags
        switch (expr->ty) {
            case EXPR_TYPE_CONST:
                new_instr = XINST_CREATE_load_int(drcontext, opnd_create_reg(op1_reg), opnd_create_immed_int(expr->op1, OPSZ_8));
                instrlist_meta_preinsert(bb, instr, new_instr);
                break;
            case EXPR_TYPE_ADD:
                new_instr = XINST_CREATE_add(drcontext, opnd_create_reg(op1_reg), opnd_create_reg(op2_reg));
                instrlist_meta_preinsert(bb, instr, new_instr);
                break;
            case EXPR_TYPE_SUB:
                new_instr = XINST_CREATE_sub(drcontext, opnd_create_reg(op1_reg), opnd_create_reg(op2_reg));
                instrlist_meta_preinsert(bb, instr, new_instr);
                break;
            case EXPR_TYPE_MUL:
#if defined(X86)
                new_instr = INSTR_CREATE_imul(drcontext, opnd_create_reg(op1_reg), opnd_create_reg(op2_reg));
#elif defined(AARCH64)
                new_instr = instr_create_1dst_3src(drcontext, OP_madd, opnd_create_reg(op1_reg), opnd_create_reg(op1_reg), opnd_create_reg(op2_reg), opnd_create_reg(DR_REG_XZR));
#else
    #error "Unsupported architecture"
#endif
                instrlist_meta_preinsert(bb, instr, new_instr);
                break;
                /*
            case EXPR_TYPE_DIV:
#if defined(X86)
                new_instr = INSTR_CREATE_div(drcontext, opnd_create_reg(op1_reg), opnd_create_reg(op2_reg));
#elif defined(AARCH64)
                new_instr = instr_create_1dst_2src(drcontext, OP_sdiv, opnd_create_reg(op1_reg), opnd_create_reg(op1_reg), opnd_create_reg(op2_reg));
#else
    #error "Unsupported architecture"
#endif
                instrlist_meta_preinsert(bb, instr, new_instr);
                break;
                */
            case EXPR_TYPE_LOAD:
                new_instr = XINST_CREATE_load(drcontext, opnd_create_reg(op1_reg), opnd_create_base_disp(op1_reg, DR_REG_NULL, 0, 0, OPSZ_8));
                instrlist_meta_preinsert(bb, instr, new_instr);
                break;
            case EXPR_TYPE_STORE:
                new_instr = XINST_CREATE_store(drcontext, opnd_create_base_disp(op1_reg, DR_REG_NULL, 0, 0, OPSZ_8), opnd_create_reg(op2_reg));
                instrlist_meta_preinsert(bb, instr, new_instr);
                break;
            case EXPR_TYPE_REG:
                new_instr = XINST_CREATE_move(drcontext, opnd_create_reg(op1_reg), opnd_create_reg(expr->op1));
                instrlist_meta_preinsert(bb, instr, new_instr);
                break;
            default:
                dr_fprintf(STDERR, "exprbuilder_compile: unknown expression type %lu\n", expr->ty);
                break;
        }

        if (expr->ty != EXPR_TYPE_STORE) {
            new_instr = XINST_CREATE_store(drcontext, opnd_create_base_disp(scratch_reg, DR_REG_NULL, 0, 8 * i, OPSZ_8), opnd_create_reg(op1_reg));
            instrlist_meta_preinsert(bb, instr, new_instr);
        }
    }

    // Unreserve the register
    drreg_unreserve_register(drcontext, bb, instr, scratch_reg);
    drreg_unreserve_register(drcontext, bb, instr, op1_reg);
    drreg_unreserve_register(drcontext, bb, instr, op2_reg);

    // Move final values into registers
    for (reg = DR_REG_START_GPR; reg <= DR_REG_STOP_GPR; reg++) {
        unsigned long handle;
        if (exprbuilder_reg_get(builder, reg, &handle)) {
            dr_fprintf(STDERR, "exprbuilder_compile: moving final value into register %lu\n", reg);
            new_instr = XINST_CREATE_load(drcontext, opnd_create_reg(reg), opnd_create_base_disp(scratch_reg, DR_REG_NULL, 0, 8 * handle, OPSZ_8));
            instrlist_meta_preinsert(bb, instr, new_instr);
            expr_free(builder, handle);
        }
    }

    return 1;
}
