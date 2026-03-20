/*
 * recompiler.c - ARM64 页级代码重编译器
 *
 * 基于现有 arm64_writer / arm64_relocator 基础设施实现。
 * 参考 Frida Gum Stalker 的重编译模型，但适配页级 1:1 偏移映射。
 */

#include "recomp_page.h"
#include "../arm64_writer.h"
#include "../arm64_relocator.h"
#include "../arm64_common.h"
#include <string.h>
#include <stdio.h>

/* ============================================================================
 * 内部辅助：判断指令是否为分支类
 * ============================================================================ */

static int is_branch_type(Arm64InsnType type) {
    switch (type) {
        case ARM64_INSN_B:
        case ARM64_INSN_BL:
        case ARM64_INSN_B_COND:
        case ARM64_INSN_CBZ:
        case ARM64_INSN_CBNZ:
        case ARM64_INSN_TBZ:
        case ARM64_INSN_TBNZ:
            return 1;
        default:
            return 0;
    }
}

/* 判断指令是否不可能 fall-through（无条件跳转/返回） */
static int is_unconditional_transfer(Arm64InsnType type) {
    return type == ARM64_INSN_B || type == ARM64_INSN_BR || type == ARM64_INSN_RET;
}

/* ============================================================================
 * 编码 B / BL 指令（手动编码，不通过 writer）
 * ============================================================================ */

static int encode_b(uint64_t from_pc, uint64_t to_pc, uint32_t* out) {
    int64_t offset = (int64_t)to_pc - (int64_t)from_pc;
    if (offset & 3) return -1;
    int64_t imm26 = offset >> 2;
    if (!fits_signed(imm26, 26)) return -1;
    *out = 0x14000000 | ((uint32_t)imm26 & 0x03FFFFFF);
    return 0;
}

static int encode_bl(uint64_t from_pc, uint64_t to_pc, uint32_t* out) {
    int64_t offset = (int64_t)to_pc - (int64_t)from_pc;
    if (offset & 3) return -1;
    int64_t imm26 = offset >> 2;
    if (!fits_signed(imm26, 26)) return -1;
    *out = 0x94000000 | ((uint32_t)imm26 & 0x03FFFFFF);
    return 0;
}

/* ============================================================================
 * 跳板生成：为超出范围的 PC 相对指令生成跳板代码
 *
 * 设计要点：
 *   - B/BL：跳板做绝对跳转（MOVZ/MOVK + BR X16）
 *   - 条件分支：跳板先判断条件，taken 绝对跳转，not-taken 跳回下一条
 *   - ADR/ADRP：跳板用 MOVZ/MOVK 加载目标地址到目标寄存器，跳回下一条
 *   - LDR literal：跳板加载原始数据地址，从中读取数据，跳回下一条
 *   - 跳回路径使用 B（相对跳转），因为跳板总是紧邻重编译页（< 128MB）
 * ============================================================================ */

/*
 * 页末 fall-through 跳板：执行原始指令后跳到下一原始页
 *
 * 非 PC 相对指令：直接复制原始指令 + 绝对跳转到 next_page
 * PC 相对指令：复用 emit_trampoline，但 return_addr = next_page
 * 页内条件分支：taken 跳回原始页内目标（内核重定向），not-taken 跳到 next_page
 */
static int emit_fallthrough_trampoline(
    Arm64Writer* w,
    const Arm64InsnInfo* info,
    uint32_t insn,
    uint64_t next_page,       /* orig_base + PAGE_SIZE */
    uint64_t orig_base        /* 用于计算页内目标 */
) {
    if (!info->is_pc_relative) {
        /* 非 PC 相对：复制原始指令 + 绝对跳转到下一页 */
        arm64_writer_put_insn(w, insn);
        arm64_writer_put_branch_address(w, next_page);
        return 0;
    }

    /* 页内条件分支：taken 跳回原始目标（内核会重定向），not-taken 跳下一页 */
    if (is_branch_type(info->type) &&
        info->target >= orig_base &&
        info->target < orig_base + RECOMP_PAGE_SIZE) {

        switch (info->type) {
        case ARM64_INSN_B_COND: {
            uint64_t taken = arm64_writer_new_label_id(w);
            arm64_writer_put_b_cond_label(w, info->cond, taken);
            /* not-taken → 下一页 */
            arm64_writer_put_branch_address(w, next_page);
            arm64_writer_put_label(w, taken);
            /* taken → 原始页内目标（内核重定向到重编译页） */
            arm64_writer_put_branch_address(w, info->target);
            break;
        }
        case ARM64_INSN_CBZ:
        case ARM64_INSN_CBNZ: {
            uint64_t taken = arm64_writer_new_label_id(w);
            if (info->type == ARM64_INSN_CBZ)
                arm64_writer_put_cbz_reg_label(w, info->reg, taken);
            else
                arm64_writer_put_cbnz_reg_label(w, info->reg, taken);
            arm64_writer_put_branch_address(w, next_page);
            arm64_writer_put_label(w, taken);
            arm64_writer_put_branch_address(w, info->target);
            break;
        }
        case ARM64_INSN_TBZ:
        case ARM64_INSN_TBNZ: {
            uint64_t taken = arm64_writer_new_label_id(w);
            if (info->type == ARM64_INSN_TBZ)
                arm64_writer_put_tbz_reg_imm_label(w, info->reg, info->bit, taken);
            else
                arm64_writer_put_tbnz_reg_imm_label(w, info->reg, info->bit, taken);
            arm64_writer_put_branch_address(w, next_page);
            arm64_writer_put_label(w, taken);
            arm64_writer_put_branch_address(w, info->target);
            break;
        }
        case ARM64_INSN_BL:
            /* BL 到页内目标：不会 fall-through（BL 跳走了），但保险起见还是处理 */
            arm64_writer_put_branch_address(w, info->target);
            break;
        default:
            arm64_writer_put_insn(w, insn);
            arm64_writer_put_branch_address(w, next_page);
            break;
        }
        return 0;
    }

    /* 其余 PC 相对指令（ADR/ADRP/LDR literal/页外分支）：
     * 复用 emit_trampoline，return_addr 改为 next_page */
    return -1; /* 返回 -1 表示调用方应使用 emit_trampoline(return_addr=next_page) */
}

static int emit_trampoline(
    Arm64Writer* w,
    const Arm64InsnInfo* info,
    uint32_t insn,
    uint64_t return_addr,  /* recomp_base + offset + 4 */
    uint64_t orig_ret_addr /* orig_base + offset + 4 (BL 用，其余传 0) */
) {
    switch (info->type) {

    /* ---- B ---- */
    case ARM64_INSN_B:
        arm64_writer_put_branch_address(w, info->target);
        break;

    /* ---- BL ---- */
    case ARM64_INSN_BL:
        /* LR 设为原始地址（让栈帧指向原始代码范围，ART 栈回溯正确）
         * 被调函数 RET → orig_addr → 内核 fault → 重定向到 recomp_addr
         * 重编译页中 BL 改为 B（不自动设 LR），LR 由跳板手动设置 */
        arm64_writer_put_mov_reg_imm(w, ARM64_REG_X30, orig_ret_addr);
        arm64_writer_put_branch_address(w, info->target);
        break;

    /* ---- B.cond ---- */
    case ARM64_INSN_B_COND: {
        /* B.!cond skip → 绝对跳转到 target → skip: B return_addr */
        uint64_t skip = arm64_writer_new_label_id(w);
        Arm64Cond inv = (Arm64Cond)(info->cond ^ 1);
        arm64_writer_put_b_cond_label(w, inv, skip);
        arm64_writer_put_branch_address(w, info->target);
        arm64_writer_put_label(w, skip);
        arm64_writer_put_b_imm(w, return_addr);
        break;
    }

    /* ---- CBZ / CBNZ ---- */
    case ARM64_INSN_CBZ:
    case ARM64_INSN_CBNZ: {
        uint64_t skip = arm64_writer_new_label_id(w);
        /* 反转条件：CBZ → CBNZ skip，CBNZ → CBZ skip */
        if (info->type == ARM64_INSN_CBZ)
            arm64_writer_put_cbnz_reg_label(w, info->reg, skip);
        else
            arm64_writer_put_cbz_reg_label(w, info->reg, skip);
        arm64_writer_put_branch_address(w, info->target);
        arm64_writer_put_label(w, skip);
        arm64_writer_put_b_imm(w, return_addr);
        break;
    }

    /* ---- TBZ / TBNZ ---- */
    case ARM64_INSN_TBZ:
    case ARM64_INSN_TBNZ: {
        uint64_t skip = arm64_writer_new_label_id(w);
        if (info->type == ARM64_INSN_TBZ)
            arm64_writer_put_tbnz_reg_imm_label(w, info->reg, info->bit, skip);
        else
            arm64_writer_put_tbz_reg_imm_label(w, info->reg, info->bit, skip);
        arm64_writer_put_branch_address(w, info->target);
        arm64_writer_put_label(w, skip);
        arm64_writer_put_b_imm(w, return_addr);
        break;
    }

    /* ---- ADR / ADRP ---- */
    case ARM64_INSN_ADR:
    case ARM64_INSN_ADRP:
        /* 用 MOVZ/MOVK 序列加载目标地址到 Xd，然后跳回 */
        arm64_writer_put_mov_reg_imm(w, info->dst_reg, info->target);
        arm64_writer_put_b_imm(w, return_addr);
        break;

    /* ---- LDR literal (GPR) ---- */
    case ARM64_INSN_LDR_LITERAL: {
        /* 自引用加载：
         *   LDR Xd, =data_addr    (加载原始数据地址)
         *   LDR Xd/Wd, [Xd]      (从原始地址读取数据)
         *   B return_addr
         */
        Arm64Reg xd = info->dst_reg;  /* 总是 Xn (0-30) */
        arm64_writer_put_ldr_reg_address(w, xd, info->target);

        uint32_t opc = (insn >> 30) & 3;
        if (opc == 0) {
            /* 32 位加载：LDR Wd, [Xd] */
            Arm64Reg wd = (Arm64Reg)(xd + 32);
            arm64_writer_put_ldr_reg_reg_offset(w, wd, xd, 0);
        } else {
            /* 64 位加载：LDR Xd, [Xd] */
            arm64_writer_put_ldr_reg_reg_offset(w, xd, xd, 0);
        }
        arm64_writer_put_b_imm(w, return_addr);
        break;
    }

    /* ---- LDRSW literal ---- */
    case ARM64_INSN_LDRSW_LITERAL: {
        Arm64Reg xd = info->dst_reg;
        arm64_writer_put_ldr_reg_address(w, xd, info->target);
        arm64_writer_put_ldrsw_reg_reg_offset(w, xd, xd, 0);
        arm64_writer_put_b_imm(w, return_addr);
        break;
    }

    /* ---- LDR literal (FP/SIMD) ---- */
    case ARM64_INSN_LDR_LITERAL_FP: {
        /* FP 寄存器不能做地址运算，用 X16 做中间寄存器 */
        arm64_writer_put_ldr_reg_address(w, ARM64_REG_X16, info->target);
        arm64_writer_put_ldr_fp_reg_reg(w, (uint32_t)info->dst_reg,
                                         ARM64_REG_X16, info->fp_size);
        arm64_writer_put_b_imm(w, return_addr);
        break;
    }

    /* ---- PRFM literal ---- */
    case ARM64_INSN_PRFM_LITERAL:
        /* 预取指令丢弃即可，直接跳回 */
        arm64_writer_put_b_imm(w, return_addr);
        break;

    default:
        /* 不应到达此处 */
        arm64_writer_put_b_imm(w, return_addr);
        break;
    }

    return 0;
}

/* ============================================================================
 * 主入口：重编译一页代码
 * ============================================================================ */

int recompile_page(
    const void* orig_code,
    uint64_t orig_base,
    void* recomp_buf,
    uint64_t recomp_base,
    void* tramp_buf,
    uint64_t tramp_base,
    size_t tramp_cap,
    size_t* tramp_used,
    RecompileStats* stats
) {
    const uint32_t* orig_insns = (const uint32_t*)orig_code;
    uint32_t* recomp_insns = (uint32_t*)recomp_buf;

    RecompileStats local_stats;
    memset(&local_stats, 0, sizeof(local_stats));

    /* 初始化跳板区 writer */
    Arm64Writer tw;
    arm64_writer_init(&tw, tramp_buf, tramp_base, tramp_cap);

    /* 逐条处理 */
    for (int i = 0; i < RECOMP_INSN_COUNT; i++) {
        uint32_t insn = orig_insns[i];
        uint64_t orig_pc  = orig_base  + (uint64_t)(i * 4);
        uint64_t recomp_pc = recomp_base + (uint64_t)(i * 4);
        int is_last = (i == RECOMP_INSN_COUNT - 1);

        /* 分析指令 */
        Arm64InsnInfo info = arm64_relocator_analyze_insn(orig_pc, insn);

        /* ================================================================
         * 页末 fall-through 修复：
         * 最后一条指令如果不是无条件跳转/返回，执行后 PC 会进入跳板区。
         * 必须强制走跳板，确保 fall-through 跳到原始下一页。
         * ================================================================ */
        if (is_last && !is_unconditional_transfer(info.type)) {
            if (!arm64_writer_can_write(&tw, 96)) {
                local_stats.error = -1;
                snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                         "跳板区空间不足 (fall-through fixup)");
                goto done;
            }

            uint64_t tramp_pc = arm64_writer_pc(&tw);
            uint64_t next_page = orig_base + RECOMP_PAGE_SIZE;

            int ft_ret = emit_fallthrough_trampoline(
                &tw, &info, insn, next_page, orig_base);

            if (ft_ret == -1) {
                /* PC 相对页外指令：复用 emit_trampoline，return_addr = next_page */
                emit_trampoline(&tw, &info, insn, next_page, next_page);
            }

            /* 替换为 B 到跳板（BL 也用 B，LR 由跳板设置） */
            uint32_t branch_insn;
            int enc_err = encode_b(recomp_pc, tramp_pc, &branch_insn);
            if (enc_err != 0) {
                local_stats.error = -1;
                snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                         "encode B failed (fall-through, offset=0x%x)", i * 4);
                goto done;
            }
            recomp_insns[i] = branch_insn;
            local_stats.num_trampolines++;
            continue;
        }

        /* 1) 非 PC 相对指令：直接复制 */
        if (!info.is_pc_relative) {
            recomp_insns[i] = insn;
            local_stats.num_copied++;
            continue;
        }

        /* 2) 页内分支：偏移不变，直接复制
         *    只对分支类指令做此优化（目标也在重编译页中执行）
         *    ADR/ADRP/LDR literal 始终引用原始地址，不做此优化 */
        if (is_branch_type(info.type) &&
            info.target >= orig_base &&
            info.target < orig_base + RECOMP_PAGE_SIZE) {
            recomp_insns[i] = insn;
            local_stats.num_intra_page++;
            continue;
        }

        /* 3) 尝试直接调整立即数 */
        uint32_t relocated;
        Arm64RelocResult rr = arm64_relocator_relocate_insn(
            orig_pc, recomp_pc, insn, &relocated);

        if (rr == ARM64_RELOC_OK) {
            recomp_insns[i] = relocated;
            local_stats.num_direct_reloc++;
            continue;
        }

        /* 4) PRFM 特殊处理：直接替换为 NOP（无需跳板） */
        if (info.type == ARM64_INSN_PRFM_LITERAL) {
            recomp_insns[i] = 0xD503201F;  /* NOP */
            local_stats.num_direct_reloc++;
            continue;
        }

        /* 5) 超出范围：生成跳板 */
        if (!arm64_writer_can_write(&tw, 64)) {
            local_stats.error = -1;
            snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                     "跳板区空间不足 (offset=0x%x)", i * 4);
            goto done;
        }

        uint64_t tramp_pc = arm64_writer_pc(&tw);
        uint64_t return_addr = recomp_pc + 4;
        uint64_t orig_ret_addr = orig_pc + 4;  /* BL 用：LR 指向原始地址 */

        /* 生成跳板代码 */
        size_t tramp_before = arm64_writer_offset(&tw);
        emit_trampoline(&tw, &info, insn, return_addr, orig_ret_addr);
        size_t tramp_after = arm64_writer_offset(&tw);

        /* 安全检查：跳板必须有内容 */
        if (tramp_after == tramp_before) {
            local_stats.error = -1;
            snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                     "空跳板 (offset=0x%x, type=%d)", i * 4, info.type);
            goto done;
        }

        /* BL 也用 B（LR 由跳板手动设置为原始地址） */
        uint32_t branch_insn;
        int enc_err = encode_b(recomp_pc, tramp_pc, &branch_insn);

        if (enc_err != 0) {
            local_stats.error = -1;
            snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                     "无法编码到跳板的分支 (offset=0x%x, tramp=0x%llx)",
                     i * 4, (unsigned long long)tramp_pc);
            goto done;
        }

        recomp_insns[i] = branch_insn;
        local_stats.num_trampolines++;
    }

    /* flush writer 的 label 引用 */
    if (arm64_writer_flush(&tw) != 0) {
        local_stats.error = -1;
        snprintf(local_stats.error_msg, sizeof(local_stats.error_msg),
                 "跳板区 label 解析失败");
    }

    /* DEBUG: dump offset 0xfbc-0xfdc 的原始 vs recomp 指令（含页基址） */
    if (local_stats.error == 0) {
        for (int d = 0xfbc/4; d <= 0xfdc/4 && d < RECOMP_INSN_COUNT; d++) {
            uint32_t orig = orig_insns[d];
            uint32_t recomp = recomp_insns[d];
            hook_log("[recomp-dump] page=%llx offset=0x%03x: orig=%08x recomp=%08x %s",
                     (unsigned long long)orig_base, d*4, orig, recomp,
                     orig != recomp ? "CHANGED" : "same");
        }
    }

    /* 在跳板区末尾填 BRK guard，防止 fall-through 到空白执行垃圾指令 */
    while (arm64_writer_can_write(&tw, 4)) {
        arm64_writer_put_brk_imm(&tw, 0xFEED);
    }

done:
    if (tramp_used)
        *tramp_used = arm64_writer_offset(&tw);

    if (stats)
        *stats = local_stats;

    arm64_writer_clear(&tw);

    return local_stats.error ? -1 : 0;
}

