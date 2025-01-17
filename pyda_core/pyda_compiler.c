#include <stdlib.h>
#include "pyda_compiler.h"
#include "pyda_core.h"
#include "pyda_util.h"
#include "drreg.h"
#include <stddef.h>

static void exprbuilder_commit(ExprBuilder *builder, instrlist_t *bb, instr_t *instr, reg_id_t scratch_ptr_reg);

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
        case EXPR_TYPE_RAW:
        case EXPR_TYPE_REG:
            // Constants don't have child expressions
            break;
        default:
            dr_fprintf(STDERR, "unimplemented validate_and_increment_refs ty %d\n", ty);
            return -1;
    }
    return 0;
}

unsigned long expr_new_raw(ExprBuilder *builder, const char *buf, size_t size) {
    void *drcontext = dr_get_current_drcontext();
    struct ExprRaw *rexpr = dr_thread_alloc(drcontext, sizeof(struct ExprRaw));
    struct Expr *expr = (struct Expr *)rexpr;

    if (!expr) {
        return (unsigned long)-1;
    }

    expr->ty = EXPR_TYPE_RAW;
    expr->op1 = 0;
    expr->op2 = 0;
    expr->refcount = 2; /* 2 since we add it to the ops array below */

    rexpr->code = instrlist_create(drcontext);

    const char *end = buf + size;
    while (buf < end) {
        instr_t *instr = instr_create(drcontext);
        instr_set_meta(instr);
        buf = (const char *)decode(drcontext, (byte *)buf, instr);
        if (buf == NULL) {
            instr_destroy(drcontext, instr);
            instrlist_clear_and_destroy(drcontext, rexpr->code);
            dr_thread_free(drcontext, expr, sizeof(struct ExprRaw));
            return (unsigned long)-1;
        }
        dr_print_instr(drcontext, STDERR, instr, "");
        instrlist_append(rexpr->code, instr);
    }

    // Add to builder's vector and return the index as handle
    unsigned int idx = builder->exprs.entries;
    drvector_append(&builder->exprs, expr);
    drvector_append(&builder->ops, (void*)(uintptr_t)idx);

    return idx;

}

unsigned long expr_new(ExprBuilder *builder, unsigned long ty, unsigned long op1, unsigned long op2) {
    void *drcontext = dr_get_current_drcontext();
    struct Expr *expr = dr_thread_alloc(drcontext, sizeof(struct Expr));
    if (!expr || ty == EXPR_TYPE_RAW) {
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

    if (ty == EXPR_TYPE_LOAD || ty == EXPR_TYPE_STORE) {
        drvector_append(&builder->ops, (void*)(uintptr_t)idx);
        expr->refcount++;
    }

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
        case EXPR_TYPE_RAW:
            if (((struct ExprRaw *)expr)->code != NULL) {
                instrlist_clear_and_destroy(drcontext, ((struct ExprRaw *)expr)->code);
                ((struct ExprRaw *)expr)->code = NULL;
            }
            break;
        default:
            dr_fprintf(STDERR, "expr_free: invalid expression type %lu\n", expr->ty);
            break;
    }

    if (expr->ty == EXPR_TYPE_RAW) {
        dr_thread_free(drcontext, expr, sizeof(struct ExprRaw));
    } else {
        dr_thread_free(drcontext, expr, sizeof(struct Expr));
    }
    builder->exprs.array[handle] = NULL;
}

ExprBuilder *exprbuilder_init() {
    ExprBuilder *builder = dr_thread_alloc(dr_get_current_drcontext(), sizeof(ExprBuilder));
    if (!builder) {
        dr_fprintf(STDERR, "Failed to allocate ExprBuilder\n");
        return NULL;
    }
    drvector_init(&builder->exprs, 0, true, NULL);
    drvector_init(&builder->ops, 0, true, NULL);
    memset(&builder->mc, 0xff, sizeof(dr_mcontext_t));
    builder->mc.size = sizeof(dr_mcontext_t);
    builder->mc.flags = DR_MC_ALL;
    return builder;
}

void exprbuilder_delete(ExprBuilder *builder) {
    for (uint i = 0; i < builder->ops.entries; i++) {
        expr_free(builder, (unsigned long)builder->ops.array[i]);
    }

    // Check for leaked expressions
    for (uint i = 0; i < builder->exprs.entries; i++) {
        struct Expr *expr = builder->exprs.array[i];
        if (expr) {
            dr_fprintf(STDERR, "Warning: expression %u leaked (refcount: %d)\n", i, expr->refcount);
            expr_free(builder, i);
        }
    }

    drvector_delete(&builder->exprs);
    drvector_delete(&builder->ops);
}

int exprbuilder_reg_get(ExprBuilder *builder, reg_id_t reg_id, unsigned long *handle) {
    reg_t idx;
    if (!reg_get_value_ex(reg_id, &builder->mc, (uint8_t*)&idx)) return 0;

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
    if (!reg_get_value_ex(reg_id, &builder->mc, (uint8_t*)&old_handle)) return 0;
    if (old_handle < builder->exprs.entries && builder->exprs.array[handle]) {
        expr_free(builder, (unsigned long)old_handle);
    }

    reg_t new_handle = handle;
    reg_set_value_ex(reg_id, &builder->mc, (uint8_t*)&new_handle);
    exprbuilder_incref(builder, handle);
    return 1;
}

extern int g_pyda_tls_idx;

int exprbuilder_compile(ExprBuilder *builder, instrlist_t *bb, instr_t *instr, int expr_handle_start) {
    void *drcontext = dr_get_current_drcontext();
    instr_t *new_instr;
    reg_id_t reg, scratch_ptr_reg;
    reg_id_t op1_reg, op2_reg;

    if (builder->exprs.entries > SCRATCH_SLOTS) {
        dr_fprintf(STDERR, "Register allocation is not yet implemented");
        return 0;
    }

    if (expr_handle_start >= builder->exprs.entries) {
        return 1;
    }

    // Reserve a register for accessing TLS
    if (drreg_reserve_register(drcontext, bb, instr, NULL, &scratch_ptr_reg) != DRREG_SUCCESS) {
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

    if (!drmgr_insert_read_tls_field(drcontext, g_pyda_tls_idx, bb, instr, scratch_ptr_reg)) {
        dr_fprintf(STDERR, "Failed to read TLS field\n");
        return 0;
    }

    opnd_t scratch_base = opnd_create_reg(scratch_ptr_reg);

    // Add offsetof(pyda_thread, scratch_region) to the base address
    new_instr = XINST_CREATE_add(drcontext, scratch_base, opnd_create_immed_int(offsetof(pyda_thread, scratch_region), OPSZ_8));
    instrlist_meta_preinsert(bb, instr, new_instr);

    // Use the scratch region for each expression
    for (unsigned long i = expr_handle_start; i < builder->exprs.entries; i++) {
        struct Expr *expr = builder->exprs.array[i];
        if (!expr) continue;

        if (expr->ty == EXPR_TYPE_RAW) {
            // Unreserve the registers
            drreg_unreserve_register(drcontext, bb, instr, op1_reg);
            drreg_unreserve_register(drcontext, bb, instr, op2_reg);
            drreg_restore_app_value(drcontext, bb, instr, op1_reg, op1_reg, false);
            drreg_restore_app_value(drcontext, bb, instr, op2_reg, op2_reg, false);

            // Commit the current abstract register state
            exprbuilder_commit(builder, bb, instr, scratch_ptr_reg);

            drreg_unreserve_register(drcontext, bb, instr, scratch_ptr_reg);
            drreg_restore_app_value(drcontext, bb, instr, scratch_ptr_reg, scratch_ptr_reg, false);

            // Emit the raw instructions
            if (((struct ExprRaw *)expr)->code == NULL) {
                dr_fprintf(STDERR, "exprbuilder_compiler: raw expr re-ruse is not supported\n");
                dr_abort();
            }

            instrlist_meta_preinsert(bb, instr, instrlist_first(((struct ExprRaw *)expr)->code));
            instrlist_init(((struct ExprRaw *)expr)->code);
            instrlist_destroy(drcontext, ((struct ExprRaw *)expr)->code);
            ((struct ExprRaw *)expr)->code = NULL;

            // Continue
            return exprbuilder_compile(builder, bb, instr, i + 1);
        }

        if (expr->ty != EXPR_TYPE_CONST && expr->ty != EXPR_TYPE_REG) {
            new_instr = XINST_CREATE_load(drcontext, opnd_create_reg(op1_reg), opnd_create_base_disp(scratch_ptr_reg, DR_REG_NULL, 0, 8 * expr->op1, OPSZ_8));
            instrlist_meta_preinsert(bb, instr, new_instr);
        }

        if (expr->ty != EXPR_TYPE_CONST && expr->ty != EXPR_TYPE_REG && expr->ty != EXPR_TYPE_LOAD) {
            new_instr = XINST_CREATE_load(drcontext, opnd_create_reg(op2_reg), opnd_create_base_disp(scratch_ptr_reg, DR_REG_NULL, 0, 8 * expr->op2, OPSZ_8));
            instrlist_meta_preinsert(bb, instr, new_instr);
        }

        // Compute the expression and store the result in the scratch region
        // XXX: We should check that none of these touch flags
        switch (expr->ty) {
            case EXPR_TYPE_CONST:
                // new_instr = XINST_CREATE_load_int(drcontext, opnd_create_reg(op1_reg), opnd_create_immed_int(expr->op1, OPSZ_8));
                // instrlist_meta_preinsert(bb, instr, new_instr);
                instrlist_insert_mov_immed_ptrsz(drcontext, expr->op1, opnd_create_reg(op1_reg), bb, instr, NULL, NULL);
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
                if (opnd_is_pc(opnd_create_reg(expr->op1))) {
                    dr_fprintf(STDERR, "exprbuilder_compile: PC is probably not what you want to read here!\n");
                }

                if (reg_is_stolen(expr->op1)) {
                    dr_insert_get_stolen_reg_value(drcontext, bb, instr, op1_reg);
                } else if (expr->op1 == op1_reg || expr->op1 == op2_reg || expr->op1 == scratch_ptr_reg) {
                    /* mov is not sufficient. the register has been brorowed. */
                    drreg_restore_app_value(drcontext, bb, instr, expr->op1, op1_reg, false);
#if defined(AARCH64)
                } else if (expr->op1 == DR_REG_SP) {
                    dr_fprintf(STDERR, "exprbuilder_compile: add sp\n");
                    new_instr = INSTR_CREATE_add_shift(drcontext, opnd_create_reg(op1_reg), opnd_create_reg(DR_REG_SP), OPND_CREATE_INT(0), OPND_CREATE_LSL(), OPND_CREATE_INT(0));
                    instrlist_meta_preinsert(bb, instr, new_instr);
#endif
                } else {
                    new_instr = XINST_CREATE_move(drcontext, opnd_create_reg(op1_reg), opnd_create_reg(expr->op1));
                    instrlist_meta_preinsert(bb, instr, new_instr);
                }
                break;
            default:
                dr_fprintf(STDERR, "exprbuilder_compile: unknown expression type %lu\n", expr->ty);
                break;
        }

        if (expr->ty != EXPR_TYPE_STORE) {
            new_instr = XINST_CREATE_store(drcontext, opnd_create_base_disp(scratch_ptr_reg, DR_REG_NULL, 0, 8 * i, OPSZ_8), opnd_create_reg(op1_reg));
            instrlist_meta_preinsert(bb, instr, new_instr);
       }
    }

    // Unreserve the register
    drreg_unreserve_register(drcontext, bb, instr, op1_reg);
    drreg_unreserve_register(drcontext, bb, instr, op2_reg);
    drreg_restore_app_value(drcontext, bb, instr, op1_reg, op1_reg, false);
    drreg_restore_app_value(drcontext, bb, instr, op2_reg, op2_reg, false);

    exprbuilder_commit(builder, bb, instr, scratch_ptr_reg);

    drreg_unreserve_register(drcontext, bb, instr, scratch_ptr_reg);
    drreg_restore_app_value(drcontext, bb, instr, scratch_ptr_reg, scratch_ptr_reg, false);

    return 1;
}

static bool handle_is_reg(ExprBuilder *builder, unsigned long handle, reg_id_t reg) {
    if (handle >= builder->exprs.entries || !builder->exprs.array[handle]) {
        return 0;
    }
    return (
        handle < builder->exprs.entries
        && builder->exprs.array[handle]
        && ((struct Expr *)builder->exprs.array[handle])->ty == EXPR_TYPE_REG
        && ((struct Expr *)builder->exprs.array[handle])->op1 == reg
    );
}

static void exprbuilder_commit(ExprBuilder *builder, instrlist_t *bb, instr_t *instr, reg_id_t scratch_ptr_reg) {
    void *drcontext = dr_get_current_drcontext();
    // Move final values into registers
    for (reg_id_t reg = DR_REG_START_GPR; reg <= DR_REG_STOP_GPR; reg++) {
        unsigned long handle;
        if (exprbuilder_reg_get(builder, reg, &handle)) {
            if (handle_is_reg(builder, handle, reg)) {
                expr_free(builder, handle);
                return;
            }

            if (reg == scratch_ptr_reg) {
                dr_fprintf(STDERR, "exprbuilder_compile: INTERNAL ERROR register %lu is scratch\n", reg);
                dr_abort();
            }

            if (opnd_is_pc(opnd_create_reg(reg))) {
                dr_fprintf(STDERR, "exprbuilder_compile: You cannot modify PC in exprbuilder\n");
                dr_abort();
            }

            DEBUG_PRINTF("exprbuilder_compile: moving final value %d into register %s\n", handle, get_register_name(reg));
            if (reg_is_stolen(reg)) {
                DEBUG_PRINTF("exprbuilder_compile: writing to stolen register %d\n", reg);
                reg_id_t tmp_reg;

                // We need to reserve a register to put the value in so we can call dr_insert_set_stolen_reg_value
                if (drreg_reserve_register(drcontext, bb, instr, NULL, &tmp_reg) != DRREG_SUCCESS) {
                    dr_fprintf(STDERR, "Failed to reserve scratch register\n");
                }

                // Load into the reserved register
                instr_t *load_instr = XINST_CREATE_load(drcontext, opnd_create_reg(tmp_reg), opnd_create_base_disp(scratch_ptr_reg, DR_REG_NULL, 0, 8 * handle, OPSZ_8));
                instrlist_meta_preinsert(bb, instr, load_instr);

                // Set the stolen reg value to the reserved register
                dr_insert_set_stolen_reg_value(drcontext, bb, instr, tmp_reg);
                drreg_unreserve_register(drcontext, bb, instr, tmp_reg);
                if (drreg_restore_all(drcontext, bb, instr) != DRREG_SUCCESS) {
                    dr_fprintf(STDERR, "Failed to drreg_restore_all\n");
                    dr_abort();
                }
            } else {
                // TODO: SP does not work here
                instr_t *load_instr = XINST_CREATE_load(drcontext, opnd_create_reg(reg), opnd_create_base_disp(scratch_ptr_reg, DR_REG_NULL, 0, 8 * handle, OPSZ_8));
                instrlist_meta_preinsert(bb, instr, load_instr);
            }
            expr_free(builder, handle);
        }
    }
}
