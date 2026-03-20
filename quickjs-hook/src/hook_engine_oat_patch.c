/*
 * hook_engine_oat_patch.c - Binary patch for inlined GetOatQuickMethodHeader
 *
 * API 31+ 的 WalkStack 内联了 GetOatQuickMethodHeader 的逻辑。
 * 对被 hook 的 replacement ArtMethod，内联代码查找 OAT 元数据失败后
 * 解引用 NULL → SIGSEGV。
 *
 * 策略 (对标 Frida maybeInstrumentGetOatQuickMethodHeaderInlineCopies):
 *   1. 扫描 libart 可执行段，用字节模式匹配找到内联的 GetOatQuickMethodHeader
 *   2. 对每个匹配点创建 trampoline:
 *      - 重定位前 2 条指令 (LDR + CMN)
 *      - 如果 data_ == -1 (runtime method) → 跳到原始 runtime 路径
 *      - 保存寄存器 → 调用 is_replacement(method) → 恢复寄存器
 *      - 如果是 replacement → 跳到 runtime 路径 (跳过 OAT 查找)
 *      - 否则 → 继续原始 OAT 查找
 *   3. 用 LDR+BR 跳转替换原始内联代码
 */

#include "hook_engine_internal.h"

/* ============================================================================
 * Pattern definitions — match inlined GetOatQuickMethodHeader in WalkStack
 *
 * ARM64 内联模式:
 *   LDR W?, [Xmethod, #0x8]   — 读 ArtMethod.data_ (32-bit)
 *   CMN W?, #0x1               — data_ == 0xFFFFFFFF? (runtime method)
 *   B.EQ/B.NE <target>         — 条件跳转
 *   <next instruction>         — OAT lookup 或 runtime 路径
 *
 * 验证: 沿 "regular method" 路径前 3 条指令中有 LDR Xt, [Xmethod, #0x18]
 * ============================================================================ */

/* Validation result from pattern match */
typedef struct {
    int     method_reg;     /* X register holding ArtMethod* (0-30) */
    int     scratch_reg;    /* X register used as scratch (W? in LDR) */
    int     branch_is_eq;   /* 1 if B.EQ (true=runtime), 0 if B.NE (true=regular) */
    uint64_t target_when_true;      /* branch taken target */
    uint64_t target_when_regular;   /* path for regular method (OAT lookup) */
    uint64_t target_when_runtime;   /* path for runtime method (skip OAT) */
} OatInlineMatch;

/* Max inline patches we track */
#define MAX_OAT_INLINE_PATCHES 16

typedef struct {
    uint64_t original_addr;     /* address of patched code in libart */
    void*    trampoline;        /* allocated trampoline */
    uint8_t  original_bytes[24]; /* saved original bytes (up to 20 needed) */
    int      patch_size;        /* bytes overwritten */
} OatInlinePatchEntry;

static OatInlinePatchEntry g_oat_patches[MAX_OAT_INLINE_PATCHES];
static int g_oat_patch_count = 0;

/* ============================================================================
 * is_replacement_in_table — check g_art_router_table for replacement match
 *
 * 从 trampoline 通过 BLR 调用: x0 = ArtMethod*, 返回 1 如果是 replacement
 * ============================================================================ */

static uint64_t is_replacement_in_table(uint64_t method) {
    for (int i = 0; i < ART_ROUTER_TABLE_MAX; i++) {
        if (g_art_router_table[i].original == 0)
            break;
        if (g_art_router_table[i].replacement == method)
            return 1;
    }
    return 0;
}

/* ============================================================================
 * Pattern scanning
 * ============================================================================ */

/*
 * ARM64 内联 GetOatQuickMethodHeader 的 3 个签名模式:
 *
 * Pattern 1: LDR W8, [X?, #0x8]; CMN W8, #0x1; B.EQ <target>; ADRP X8, ...
 *   → regular method 路径在 B.EQ 后面 (fall-through)
 *
 * Pattern 2: LDR W8, [X?, #0x8]; CMN W8, #0x1; B.EQ <target>; LDR X?, [X?, #0x18]
 *   → regular method 路径在 B.EQ 后面
 *
 * Pattern 3: LDR W8, [X?, #0x8]; CMN W8, #0x1; B.NE <target>; MOV X0, XZR
 *   → runtime method 路径在 B.NE 后面 (fall-through), regular 在 B.NE taken
 */

/* Decode ARM64 instruction fields */
static inline int decode_ldr_w_base(uint32_t insn) {
    /* LDR Wt, [Xn, #imm12]:  1011 1001 01ii iiii iiii iinn nnnt tttt
     * Check: size=10, V=0, opc=01, imm12 = 0x8/4=2 */
    if ((insn & 0xFFC00000) != 0xB9400000) return -1;
    uint32_t imm12 = (insn >> 10) & 0xFFF;
    if (imm12 != 2) return -1;  /* offset #0x8 scaled by 4 = imm12=2 */
    return (insn >> 5) & 0x1F;  /* Rn = base register */
}

static inline int decode_ldr_w_dst(uint32_t insn) {
    if ((insn & 0xFFC00000) != 0xB9400000) return -1;
    return insn & 0x1F;  /* Rt = destination register */
}

static inline int is_cmn_w_1(uint32_t insn) {
    /* CMN Wn, #1 = ADDS WZR, Wn, #1
     * 0011 0001 0000 0000 0000 01nn nnn1 1111
     * mask:    ff fc 03 e0 → 0x3100041F with Rn variable */
    return (insn & 0xFFFFFC1F) == 0x3100041F;
}

static inline int decode_b_cond(uint32_t insn, uint64_t pc, int* cond_out, uint64_t* target_out) {
    /* B.cond: 0101 0100 iiii iiii iiii iiii iii0 cccc
     * imm19 = bits [23:5], sign-extended, shifted left 2 */
    if ((insn & 0xFF000010) != 0x54000000) return 0;
    *cond_out = insn & 0xF;
    int32_t imm19 = (int32_t)((insn >> 5) & 0x7FFFF);
    if (imm19 & 0x40000) imm19 |= (int32_t)0xFFF80000;  /* sign-extend */
    *target_out = pc + ((int64_t)imm19 << 2);
    return 1;
}

static inline int is_ldr_x_offset_0x18(uint32_t insn, int expected_base) {
    /* LDR Xt, [Xn, #0x18]: 1111 1001 01ii iiii iiii iinn nnnt tttt
     * size=11, V=0, opc=01, imm12 = 0x18/8=3 */
    if ((insn & 0xFFC00000) != 0xF9400000) return 0;
    uint32_t imm12 = (insn >> 10) & 0xFFF;
    if (imm12 != 3) return 0;  /* offset #0x18 scaled by 8 = imm12=3 */
    int base = (insn >> 5) & 0x1F;
    return (base == expected_base);
}

/*
 * Validate a candidate match at addr (must be instruction-aligned).
 * addr points to the LDR W?, [Xn, #0x8] instruction.
 * scan_base/scan_size define the readable region for bounds checking.
 *
 * Returns 1 on valid match, fills out match info.
 */
static int validate_oat_inline_match(uint64_t addr, uint8_t* code_buf,
                                      uint64_t scan_base, size_t scan_size,
                                      OatInlineMatch* out) {
    uint32_t insn0 = *(uint32_t*)(code_buf);      /* LDR W?, [Xn, #0x8] */
    uint32_t insn1 = *(uint32_t*)(code_buf + 4);  /* CMN W?, #0x1 */
    uint32_t insn2 = *(uint32_t*)(code_buf + 8);  /* B.cond */

    /* Instruction 0: LDR Wt, [Xn, #0x8] */
    int method_reg = decode_ldr_w_base(insn0);
    if (method_reg < 0) return 0;
    int scratch_reg = decode_ldr_w_dst(insn0);
    if (scratch_reg < 0) return 0;

    /* Instruction 1: CMN Wt, #1 (where Wt matches insn0's Rt) */
    if (!is_cmn_w_1(insn1)) return 0;
    int cmn_rn = (insn1 >> 5) & 0x1F;
    if (cmn_rn != scratch_reg) return 0;

    /* Instruction 2: B.EQ or B.NE */
    int cond;
    uint64_t branch_target;
    if (!decode_b_cond(insn2, addr + 8, &cond, &branch_target)) return 0;
    if (cond != ARM64_COND_EQ && cond != ARM64_COND_NE) return 0;

    int branch_is_eq = (cond == ARM64_COND_EQ);

    uint64_t target_when_true = branch_target;
    uint64_t target_when_false = addr + 12;  /* fall-through */

    uint64_t target_when_regular, target_when_runtime;
    if (branch_is_eq) {
        /* B.EQ: true → runtime, false → regular (OAT lookup) */
        target_when_regular = target_when_false;
        target_when_runtime = target_when_true;
    } else {
        /* B.NE: true → regular, false → runtime */
        target_when_regular = target_when_true;
        target_when_runtime = target_when_false;
    }

    /* Validation: in the "regular method" path, within 3 instructions,
     * there should be LDR Xt, [Xmethod, #0x18].
     * Check that the target is within our known readable scan range. */
    int found_ldr_0x18 = 0;
    uint64_t scan_end = scan_base + scan_size;
    if (target_when_regular >= scan_base && target_when_regular + 12 <= scan_end) {
        const uint32_t* reg_code = (const uint32_t*)target_when_regular;
        for (int i = 0; i < 3; i++) {
            if (is_ldr_x_offset_0x18(reg_code[i], method_reg)) {
                found_ldr_0x18 = 1;
                break;
            }
        }
    }
    if (!found_ldr_0x18) return 0;

    out->method_reg = method_reg;
    out->scratch_reg = scratch_reg;
    out->branch_is_eq = branch_is_eq;
    out->target_when_true = target_when_true;
    out->target_when_regular = target_when_regular;
    out->target_when_runtime = target_when_runtime;
    return 1;
}

/*
 * Scan a memory range for the inlined GetOatQuickMethodHeader pattern.
 * Returns number of matches found and fills match_addrs/match_infos.
 */
static int scan_for_oat_inline_patterns(
    uint64_t scan_base, size_t scan_size,
    uint64_t full_base, size_t full_size,
    uint64_t match_addrs[], OatInlineMatch match_infos[], int max_matches)
{
    int count = 0;

    /* Scan directly from memory — libart r-x pages are readable.
     * Verify readability once; if not readable, use read_target_safe fallback. */
    int direct_read = page_has_read_perm(scan_base);

    if (direct_read) {
        /* Fast path: scan memory directly as uint32_t array */
        const uint32_t* code = (const uint32_t*)scan_base;
        size_t num_insns = scan_size / 4;

        for (size_t i = 0; i + 4 <= num_insns; i++) {
            if (count >= max_matches) break;

            uint32_t insn0 = code[i];
            /* Quick pre-check: is this LDR Wt, [Xn, #0x8]? */
            if ((insn0 & 0xFFC00000) != 0xB9400000) continue;
            uint32_t imm12 = (insn0 >> 10) & 0xFFF;
            if (imm12 != 2) continue;

            uint64_t addr = scan_base + i * 4;
            OatInlineMatch match;
            if (validate_oat_inline_match(addr, (uint8_t*)&code[i], full_base, full_size, &match)) {
                match_addrs[count] = addr;
                match_infos[count] = match;
                count++;
            }
        }
    } else {
        /* Slow fallback: read via read_target_safe (XOM pages) */
        for (uint64_t addr = scan_base; addr + 16 <= scan_base + scan_size; addr += 4) {
            if (count >= max_matches) break;

            uint8_t buf[16];
            if (read_target_safe((void*)addr, buf, 16) != 0) continue;

            uint32_t insn0 = *(uint32_t*)(buf);
            if ((insn0 & 0xFFC00000) != 0xB9400000) continue;
            uint32_t imm12 = (insn0 >> 10) & 0xFFF;
            if (imm12 != 2) continue;

            OatInlineMatch match;
            if (validate_oat_inline_match(addr, buf, full_base, full_size, &match)) {
                match_addrs[count] = addr;
                match_infos[count] = match;
                count++;
            }
        }
    }

    return count;
}

/* ============================================================================
 * Trampoline generation
 *
 * 对每个匹配点, 生成 trampoline:
 *   1. 重定位前 2 条指令 (LDR W?, [Xn, #8] + CMN W?, #1)
 *   2. B.EQ → label runtime_or_replacement (如果 data_ == -1)
 *   3. 保存 caller-saved 寄存器 (d0-d7, x0-x17)
 *   4. MOV X0, Xmethod → BLR is_replacement_in_table
 *   5. CMP X0, XZR
 *   6. 恢复寄存器
 *   7. B.NE → label runtime_or_replacement (如果是 replacement)
 *   8. B → label regular_method
 *   9. label regular_method / runtime_or_replacement:
 *      重定位第 4 条指令 + 跳回
 *      或直接跳到 target_when_true
 * ============================================================================ */

static void* generate_oat_inline_trampoline(
    uint64_t patch_addr,
    uint8_t* original_bytes,
    int patch_size,
    OatInlineMatch* match)
{
    /* Allocate trampoline from exec pool */
    void* trampoline = hook_alloc_near(512, (void*)(uintptr_t)patch_addr);
    if (!trampoline) {
        hook_log("[oat_patch] trampoline alloc failed");
        return NULL;
    }

    Arm64Writer w;
    arm64_writer_init(&w, trampoline, (uint64_t)trampoline, 512);

    /* Labels */
    uint64_t lbl_runtime_or_replacement = arm64_writer_new_label_id(&w);
    uint64_t lbl_regular_method = arm64_writer_new_label_id(&w);

    /* --- Step 1: Relocate instructions covered by the redirect ---
     * 前 3 条已知: LDR + CMN + B.EQ (12 bytes)。
     * 如果 redirect > 12 bytes，额外的指令也需要 relocate。 */
    Arm64Relocator reloc;
    arm64_relocator_init(&reloc, original_bytes, patch_addr, &w);
    arm64_relocator_read_one(&reloc);  /* LDR */
    arm64_relocator_write_one(&reloc);
    arm64_relocator_read_one(&reloc);  /* CMN */
    arm64_relocator_write_one(&reloc);

    /* --- Step 2: B.EQ → runtime_or_replacement (data_ == -1) --- */
    /* Skip original B.cond, replace with our own */
    arm64_relocator_read_one(&reloc);
    arm64_relocator_skip_one(&reloc);

    /* Relocate any extra instructions covered by the redirect (beyond the 3 known ones) */
    int relocated_bytes = 12; /* LDR(4) + CMN(4) + B.EQ(4) */
    while (relocated_bytes < patch_size && !arm64_relocator_eoi(&reloc)) {
        arm64_relocator_read_one(&reloc);
        arm64_relocator_write_one(&reloc);
        relocated_bytes += 4;
    }
    arm64_writer_put_b_cond_label(&w, ARM64_COND_EQ, lbl_runtime_or_replacement);

    /* --- Step 3: Save caller-saved registers --- */
    /* Stack frame layout (total 208 bytes, 16-byte aligned):
     *   [SP + 0]    x0, x1
     *   [SP + 16]   x2, x3
     *   [SP + 32]   x4, x5
     *   [SP + 48]   x6, x7
     *   [SP + 64]   x8, x9
     *   [SP + 80]   x10, x11
     *   [SP + 96]   x12, x13
     *   [SP + 112]  x14, x15
     *   [SP + 128]  x16, x17
     *   [SP + 144]  d0, d1
     *   [SP + 160]  d2, d3
     *   [SP + 176]  d4, d5
     *   [SP + 192]  d6, d7
     */
    #define OAT_SAVE_FRAME_SIZE 208
    arm64_writer_put_sub_reg_reg_imm(&w, ARM64_REG_SP, ARM64_REG_SP, OAT_SAVE_FRAME_SIZE);
    /* x0-x17 */
    arm64_writer_put_stp_reg_reg_reg_offset(&w, ARM64_REG_X0, ARM64_REG_X1,
        ARM64_REG_SP, 0, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(&w, ARM64_REG_X2, ARM64_REG_X3,
        ARM64_REG_SP, 16, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(&w, ARM64_REG_X4, ARM64_REG_X5,
        ARM64_REG_SP, 32, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(&w, ARM64_REG_X6, ARM64_REG_X7,
        ARM64_REG_SP, 48, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(&w, ARM64_REG_X8, ARM64_REG_X9,
        ARM64_REG_SP, 64, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(&w, ARM64_REG_X10, ARM64_REG_X11,
        ARM64_REG_SP, 80, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(&w, ARM64_REG_X12, ARM64_REG_X13,
        ARM64_REG_SP, 96, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(&w, ARM64_REG_X14, ARM64_REG_X15,
        ARM64_REG_SP, 112, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_stp_reg_reg_reg_offset(&w, ARM64_REG_X16, ARM64_REG_X17,
        ARM64_REG_SP, 128, ARM64_INDEX_SIGNED_OFFSET);
    /* d0-d7 */
    arm64_writer_put_fp_stp_offset(&w, 0, 1, ARM64_REG_SP, 144);
    arm64_writer_put_fp_stp_offset(&w, 2, 3, ARM64_REG_SP, 160);
    arm64_writer_put_fp_stp_offset(&w, 4, 5, ARM64_REG_SP, 176);
    arm64_writer_put_fp_stp_offset(&w, 6, 7, ARM64_REG_SP, 192);

    /* --- Step 4: Call is_replacement_in_table(method) --- */
    /* MOV X0, Xmethod */
    arm64_writer_put_mov_reg_reg(&w, ARM64_REG_X0,
        (Arm64Reg)(ARM64_REG_X0 + match->method_reg));
    /* LDR X16, =is_replacement_in_table; BLR X16 */
    arm64_writer_put_call_address(&w, (uint64_t)is_replacement_in_table);

    /* --- Step 5: CMP X0, XZR --- */
    arm64_writer_put_cmp_reg_reg(&w, ARM64_REG_X0, ARM64_REG_XZR);

    /* --- Step 6: Restore registers --- */
    /* d0-d7 */
    arm64_writer_put_fp_ldp_offset(&w, 0, 1, ARM64_REG_SP, 144);
    arm64_writer_put_fp_ldp_offset(&w, 2, 3, ARM64_REG_SP, 160);
    arm64_writer_put_fp_ldp_offset(&w, 4, 5, ARM64_REG_SP, 176);
    arm64_writer_put_fp_ldp_offset(&w, 6, 7, ARM64_REG_SP, 192);
    /* x0-x17 */
    arm64_writer_put_ldp_reg_reg_reg_offset(&w, ARM64_REG_X0, ARM64_REG_X1,
        ARM64_REG_SP, 0, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(&w, ARM64_REG_X2, ARM64_REG_X3,
        ARM64_REG_SP, 16, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(&w, ARM64_REG_X4, ARM64_REG_X5,
        ARM64_REG_SP, 32, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(&w, ARM64_REG_X6, ARM64_REG_X7,
        ARM64_REG_SP, 48, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(&w, ARM64_REG_X8, ARM64_REG_X9,
        ARM64_REG_SP, 64, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(&w, ARM64_REG_X10, ARM64_REG_X11,
        ARM64_REG_SP, 80, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(&w, ARM64_REG_X12, ARM64_REG_X13,
        ARM64_REG_SP, 96, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(&w, ARM64_REG_X14, ARM64_REG_X15,
        ARM64_REG_SP, 112, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_ldp_reg_reg_reg_offset(&w, ARM64_REG_X16, ARM64_REG_X17,
        ARM64_REG_SP, 128, ARM64_INDEX_SIGNED_OFFSET);
    arm64_writer_put_add_reg_reg_imm(&w, ARM64_REG_SP, ARM64_REG_SP, OAT_SAVE_FRAME_SIZE);

    /* --- Step 7: B.NE → runtime_or_replacement (is_replacement returned 1) --- */
    arm64_writer_put_b_cond_label(&w, ARM64_COND_NE, lbl_runtime_or_replacement);

    /* --- Step 8: Fall through to regular_method path --- */
    arm64_writer_put_b_label(&w, lbl_regular_method);

    /* --- Emit "regular_method" and "runtime_or_replacement" tails --- */
    /*
     * We overwrite 4 instructions (16 bytes) at patch_addr using a compact
     * LDR+BR+.quad redirect. Instructions 0-2 (LDR+CMN+B.cond) are relocated
     * above. Instruction 3 (the 4th, at patch_addr+12) must be relocated in
     * the fall-through tail, with a jump back to patch_addr + 16.
     *
     * If branch_is_eq (B.EQ → runtime, fall-through → regular):
     *   - insn3 is the start of "regular_method" path
     *   - label regular_method: relocate insn3, jump to patch_addr + 16
     *   - label runtime_or_replacement: jump to target_when_true (runtime)
     * If !branch_is_eq (B.NE → regular, fall-through → runtime):
     *   - insn3 is the start of "runtime" path
     *   - label regular_method: jump to target_when_true (regular)
     *   - label runtime_or_replacement: relocate insn3, jump to patch_addr + 16
     */
    if (match->branch_is_eq) {
        /* regular_method: relocate insn3, continue original code */
        arm64_writer_put_label(&w, lbl_regular_method);
        arm64_relocator_read_one(&reloc);  /* insn3 */
        arm64_relocator_write_one(&reloc);
        arm64_writer_put_branch_address(&w, patch_addr + 16);

        /* runtime_or_replacement: jump to original runtime target */
        arm64_writer_put_label(&w, lbl_runtime_or_replacement);
        arm64_writer_put_branch_address(&w, match->target_when_true);
    } else {
        /* regular_method: jump to original branch target (regular method path) */
        arm64_writer_put_label(&w, lbl_regular_method);
        arm64_writer_put_branch_address(&w, match->target_when_true);

        /* runtime_or_replacement: relocate insn3, continue as runtime */
        arm64_writer_put_label(&w, lbl_runtime_or_replacement);
        arm64_relocator_read_one(&reloc);  /* insn3 */
        arm64_relocator_write_one(&reloc);
        arm64_writer_put_branch_address(&w, patch_addr + 16);
    }

    if (arm64_writer_flush(&w) != 0) {
        hook_log("[oat_patch] trampoline flush failed");
        arm64_writer_clear(&w);
        arm64_relocator_clear(&reloc);
        return NULL;
    }

    size_t code_size = arm64_writer_offset(&w);
    hook_flush_cache(trampoline, code_size);

    arm64_writer_clear(&w);
    arm64_relocator_clear(&reloc);

    hook_log("[oat_patch] trampoline at %p, size=%zu, method_reg=x%d",
             trampoline, code_size, match->method_reg);
    return trampoline;
}

/* ============================================================================
 * Patch the original code in libart
 *
 * Replace 4 instructions (16 bytes) with:
 *   LDR Xscratch, =trampoline
 *   BR Xscratch
 *   (remaining bytes: NOP padding)
 * ============================================================================ */

static int apply_oat_inline_patch(
    uint64_t patch_addr,
    void* trampoline,
    OatInlineMatch* match,
    uint8_t* saved_original,
    int* patch_size_out)
{
    int scratch = match->scratch_reg;
    /* Use Xscratch (64-bit version of the W scratch register) for the jump.
     * Since the original code only uses Wscratch (which is clobbered by the
     * LDR that was relocated to the trampoline), using Xscratch is safe. */
    Arm64Reg scratch_reg = (Arm64Reg)(ARM64_REG_X0 + scratch);

    /* 复用通用 hook_write_jump（ADRP=12B 或 MOVZ=16B，不 pad BRK，wxshadow 安全）。 */
    uint8_t redirect[MIN_HOOK_SIZE];
    int jump_len = hook_write_jump(redirect, trampoline);
    if (jump_len < 0) {
        hook_log("[oat_patch] hook_write_jump failed: %d", jump_len);
        return -1;
    }

    int overwrite = jump_len;

    /* Save original bytes */
    read_target_safe((void*)patch_addr, saved_original, overwrite);
    *patch_size_out = overwrite;

    /* Apply patch: try wxshadow first, fall back to mprotect */
    size_t page_size = g_engine.exec_mem_page_size;
    uintptr_t page_start = patch_addr & ~(page_size - 1);

    if (wxshadow_patch((void*)patch_addr, redirect, overwrite) == 0) {
        hook_log("[oat_patch] applied via wxshadow at %#lx", (unsigned long)patch_addr);
    } else {
        /* Fall back to mprotect RWX → write → RX */
        /* Determine how many pages to mprotect */
        uintptr_t patch_end = patch_addr + overwrite;
        uintptr_t page_end = (patch_end + page_size - 1) & ~(page_size - 1);
        size_t mprotect_size = page_end - page_start;

        if (mprotect((void*)page_start, mprotect_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            hook_log("[oat_patch] mprotect RWX failed at %#lx: %s",
                     (unsigned long)page_start, strerror(errno));
            return -1;
        }

        memcpy((void*)patch_addr, redirect, overwrite);

        mprotect((void*)page_start, mprotect_size, PROT_READ | PROT_EXEC);
    }

    hook_flush_cache((void*)patch_addr, overwrite);
    return 0;
}

/* ============================================================================
 * Find libart base and size from /proc/self/maps
 * ============================================================================ */

/*
 * Find libart executable range and full mapped range.
 * exec_base/exec_size: only --x segments (for scanning)
 * full_base/full_size: all libart segments (for bounds checking)
 */
static int find_libart_range(uint64_t* exec_base, size_t* exec_size,
                              uint64_t* full_base, size_t* full_size) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return -1;

    uint64_t first_exec = 0, last_exec_end = 0;
    uint64_t first_any = 0, last_any_end = 0;
    char line[512];

    while (fgets(line, sizeof(line), f)) {
        uintptr_t start, end;
        char perms[8];
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) < 3) continue;
        if (!strstr(line, "libart.so")) continue;

        /* Track full range (all segments) */
        if (first_any == 0) first_any = start;
        if (end > last_any_end) last_any_end = end;

        /* Track exec range (x segments only) */
        if (perms[2] == 'x') {
            if (first_exec == 0) first_exec = start;
            if (end > last_exec_end) last_exec_end = end;
        }
    }

    fclose(f);

    if (first_exec == 0) return -1;

    *exec_base = first_exec;
    *exec_size = last_exec_end - first_exec;
    *full_base = first_any;
    *full_size = last_any_end - first_any;
    return 0;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

int hook_patch_inlined_oat_header_checks(void) {
    if (!g_engine.initialized) {
        hook_log("[oat_patch] hook engine not initialized");
        return HOOK_ERROR_NOT_INITIALIZED;
    }

    /* Find libart executable + full range */
    uint64_t exec_base, full_base;
    size_t exec_size, full_size;
    if (find_libart_range(&exec_base, &exec_size, &full_base, &full_size) != 0) {
        hook_log("[oat_patch] failed to find libart.so executable range");
        return HOOK_ERROR_NOT_FOUND;
    }

    hook_log("[oat_patch] scanning libart: exec=%#lx+%zu, full=%#lx+%zu",
             (unsigned long)exec_base, exec_size,
             (unsigned long)full_base, full_size);

    /* Scan exec segments for patterns, use full range for validation bounds */
    uint64_t match_addrs[MAX_OAT_INLINE_PATCHES];
    OatInlineMatch match_infos[MAX_OAT_INLINE_PATCHES];
    int match_count = scan_for_oat_inline_patterns(
        exec_base, exec_size, full_base, full_size,
        match_addrs, match_infos, MAX_OAT_INLINE_PATCHES);

    hook_log("[oat_patch] found %d inlined GetOatQuickMethodHeader patterns", match_count);

    if (match_count == 0) {
        return 0;  /* No patterns found — not an error (may be pre-API 31) */
    }

    int patched = 0;
    for (int i = 0; i < match_count && g_oat_patch_count < MAX_OAT_INLINE_PATCHES; i++) {
        OatInlinePatchEntry* entry = &g_oat_patches[g_oat_patch_count];

        /* Read original bytes for relocator and backup (5 instructions = 20 bytes) */
        uint8_t orig_bytes[24];
        if (read_target_safe((void*)match_addrs[i], orig_bytes, 24) != 0) {
            hook_log("[oat_patch] failed to read original bytes at %#lx",
                     (unsigned long)match_addrs[i]);
            continue;
        }

        /* Generate trampoline — patch_size 由 hook_write_jump 动态决定 (12 or 16) */
        uint8_t tmp_jump[MIN_HOOK_SIZE];
        int tmp_len = hook_write_jump(tmp_jump, (void*)(uintptr_t)match_addrs[i]);
        int tramp_patch_size = (tmp_len > 0) ? tmp_len : 16;
        void* trampoline = generate_oat_inline_trampoline(
            match_addrs[i], orig_bytes, tramp_patch_size, &match_infos[i]);
        if (!trampoline) continue;

        /* Apply the patch */
        int patch_size;
        if (apply_oat_inline_patch(match_addrs[i], trampoline, &match_infos[i],
                                    entry->original_bytes, &patch_size) != 0) {
            hook_log("[oat_patch] failed to apply patch at %#lx",
                     (unsigned long)match_addrs[i]);
            continue;
        }

        entry->original_addr = match_addrs[i];
        entry->trampoline = trampoline;
        entry->patch_size = patch_size;
        g_oat_patch_count++;
        patched++;

        hook_log("[oat_patch] patched inlined GetOatQuickMethodHeader at %#lx (method_reg=x%d, %s)",
                 (unsigned long)match_addrs[i],
                 match_infos[i].method_reg,
                 match_infos[i].branch_is_eq ? "B.EQ→runtime" : "B.NE→regular");
    }

    hook_log("[oat_patch] done: %d/%d patterns patched", patched, match_count);
    return patched;
}

int hook_restore_inlined_oat_header_patches(void) {
    int restored = 0;
    for (int i = 0; i < g_oat_patch_count; i++) {
        OatInlinePatchEntry* entry = &g_oat_patches[i];
        if (entry->original_addr == 0) continue;

        size_t page_size = g_engine.exec_mem_page_size;
        uintptr_t page_start = entry->original_addr & ~(page_size - 1);

        /* Try wxshadow release first */
        if (wxshadow_release((void*)entry->original_addr) == 0) {
            /* wxshadow release restores original automatically */
        } else {
            /* Fall back to mprotect + write */
            uintptr_t patch_end = entry->original_addr + entry->patch_size;
            uintptr_t page_end = (patch_end + page_size - 1) & ~(page_size - 1);
            size_t mprotect_size = page_end - page_start;

            if (mprotect((void*)page_start, mprotect_size,
                         PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
                memcpy((void*)entry->original_addr, entry->original_bytes, entry->patch_size);
                mprotect((void*)page_start, mprotect_size, PROT_READ | PROT_EXEC);
            }
        }

        hook_flush_cache((void*)entry->original_addr, entry->patch_size);
        entry->original_addr = 0;
        restored++;
    }

    g_oat_patch_count = 0;
    hook_log("[oat_patch] restored %d patches", restored);
    return restored;
}
