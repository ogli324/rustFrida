//! ArtMethod resolution, entry_point access, ART bridge function discovery, field cache
//!
//! Contains: resolve_art_method, read_entry_point, find_art_bridge_functions,
//! ArtBridgeFunctions, CachedFieldInfo, FIELD_CACHE, cache_fields_for_class.

use crate::jsapi::console::output_message;
use crate::jsapi::module::{libart_dlsym, dlsym_first_match, is_in_libart};
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::{Mutex, OnceLock};

use super::PAC_STRIP_MASK;
use super::jni_core::*;
use super::reflect::*;
use super::safe_mem::{refresh_mem_regions, safe_read_u64};

// ============================================================================
// 共享 Runtime 布局辅助函数
// ============================================================================

/// 根据 API 级别和 java_vm_ 偏移计算 classLinker_ 在 Runtime 中的候选偏移列表。
///
/// 共享于 find_classlinker_trampolines 和 probe_art_runtime_spec。
/// 对标 Frida android.js:649-662。
fn compute_classlinker_candidates(java_vm_off: usize) -> Vec<usize> {
    const STD_STRING_SIZE: usize = 3 * 8;
    const PTR_SIZE: usize = 8;

    let api_level = get_android_api_level();
    let codename = get_android_codename();
    let is_34_equiv = is_api_level_34_or_apex_equivalent();

    if api_level >= 33 || codename == "Tiramisu" || is_34_equiv {
        vec![java_vm_off - 4 * PTR_SIZE]
    } else if api_level >= 30 || codename == "R" || codename == "S" {
        vec![java_vm_off - 3 * PTR_SIZE, java_vm_off - 4 * PTR_SIZE]
    } else if api_level >= 29 || codename == "Q" {
        vec![java_vm_off - 2 * PTR_SIZE]
    } else if api_level >= 27 {
        vec![java_vm_off - STD_STRING_SIZE - 3 * PTR_SIZE]
    } else {
        vec![java_vm_off - STD_STRING_SIZE - 2 * PTR_SIZE]
    }
}

// ============================================================================
// ArtField layout — 按 API level 硬编码 (对标 Frida getArtFieldSpec)
// ============================================================================

/// ArtField 结构体字段偏移规格
pub(super) struct ArtFieldSpec {
    pub size: usize,
    pub access_flags_offset: usize,
}

static ART_FIELD_SPEC: OnceLock<Option<ArtFieldSpec>> = OnceLock::new();

/// 获取 ArtField 布局规格（按 API level 硬编码，对标 Frida getArtFieldSpec）
///
/// API >= 23 (Android 6+): size=16, access_flags_offset=4
/// API 21-22 (Android 5.x): size=24, access_flags_offset=12
/// API < 21: 不支持
pub(super) fn get_art_field_spec() -> Option<&'static ArtFieldSpec> {
    ART_FIELD_SPEC.get_or_init(|| {
        let api_level = get_android_api_level();
        if api_level >= 23 {
            Some(ArtFieldSpec { size: 16, access_flags_offset: 4 })
        } else if api_level >= 21 {
            Some(ArtFieldSpec { size: 24, access_flags_offset: 12 })
        } else {
            None
        }
    }).as_ref()
}

// ============================================================================
// ART bridge functions — ART internal trampoline addresses
// ============================================================================

/// ART 内部桥接函数地址集合
/// 当前仅使用 quick_generic_jni_trampoline，其余保留以备后用
#[allow(dead_code)]
pub(super) struct ArtBridgeFunctions {
    /// art_quick_generic_jni_trampoline — JNI native method 分发入口
    pub(super) quick_generic_jni_trampoline: u64,
    /// art_quick_to_interpreter_bridge — 编译代码到解释器的桥接
    pub(super) quick_to_interpreter_bridge: u64,
    /// art_quick_resolution_trampoline — 方法解析 trampoline
    pub(super) quick_resolution_trampoline: u64,
    /// art_quick_imt_conflict_trampoline — 接口方法分发冲突 trampoline
    pub(super) quick_imt_conflict_trampoline: u64,
    /// Nterp 解释器入口点（Android 12+），0 表示不可用
    pub(super) nterp_entry_point: u64,
    /// art::interpreter::DoCall<> 模板实例地址（最多4个）
    pub(super) do_call_addrs: Vec<u64>,
    /// GC 同步: ConcurrentCopying::CopyingPhase 地址，0 表示不可用
    pub(super) gc_copying_phase: u64,
    /// GC 同步: Heap::CollectGarbageInternal 地址，0 表示不可用
    pub(super) gc_collect_internal: u64,
    /// GC 同步: Thread::RunFlipFunction 地址，0 表示不可用
    pub(super) run_flip_function: u64,
    /// ArtMethod::GetOatQuickMethodHeader 地址，0 表示不可用
    pub(super) get_oat_quick_method_header: u64,
    /// ClassLinker::FixupStaticTrampolines / MakeInitializedClassesVisiblyInitialized 地址，0 表示不可用
    pub(super) fixup_static_trampolines: u64,
    /// art::Thread::Current() 函数地址，用于递归防护中获取当前线程
    pub(super) thread_current: u64,
    /// ArtMethod::PrettyMethod 函数地址，用于 NULL 指针崩溃防护
    pub(super) pretty_method: u64,
    /// 从 trampoline 解析出的真实 quick entrypoint（用于 entrypoint 比较）
    /// trampoline 通常是一条 LDR Xn, [Thread, #offset] 指令，实际入口在 Thread TLS 中
    pub(super) resolved_jni_entrypoint: u64,
    pub(super) resolved_interpreter_bridge_entrypoint: u64,
    pub(super) resolved_resolution_entrypoint: u64,
}

unsafe impl Send for ArtBridgeFunctions {}
unsafe impl Sync for ArtBridgeFunctions {}

/// 全局缓存的 ART bridge 函数地址
pub(super) static ART_BRIDGE_FUNCTIONS: std::sync::OnceLock<ArtBridgeFunctions> = std::sync::OnceLock::new();

/// 从 trampoline 地址解析真实的 quick entrypoint。
///
/// ART trampoline 的第一条指令通常是 `LDR Xn, [Xm, #offset]`，
/// 从 Thread TLS 中加载真实入口点地址。本函数读取该指令，提取 offset，
/// 然后通过 JNIEnv → Thread* 读取实际入口点。
///
/// 如果第一条指令不是 LDR 格式或 trampoline 为 0，则返回 trampoline 本身（fallback）。
unsafe fn resolve_quick_entrypoint_from_trampoline(trampoline: u64, env: JniEnv) -> u64 {
    if trampoline == 0 {
        return 0;
    }

    // 读取 trampoline 地址处的第一条 ARM64 指令
    let insn = *(trampoline as *const u32);

    // 检查是否是 LDR Xn, [Xm, #imm] 格式 (unsigned offset)
    // 编码: 1111 1001 01xx xxxx xxxx xxxx xxxx xxxx
    // mask: FFC0_0000, expected: F940_0000
    if (insn & 0xFFC0_0000) != 0xF940_0000 {
        // 不是 LDR 指令，返回 trampoline 本身
        return trampoline;
    }

    // 提取 imm12 (bits [21:10])，单位为 8 字节（64 位 LDR 的 scale）
    let imm12 = ((insn >> 10) & 0xFFF) as u64;
    let offset = imm12 * 8;

    // 从 JNIEnv 获取 Thread*: *(env + 8) 即 JNIEnvExt.self_
    let thread = *((env as usize + 8) as *const u64) & PAC_STRIP_MASK;
    if thread == 0 {
        return trampoline;
    }

    // 读取 *(thread + offset) 作为 resolved entrypoint
    let resolved = *((thread as usize + offset as usize) as *const u64) & PAC_STRIP_MASK;
    if resolved != 0 {
        output_message(&format!(
            "[art bridge] 解析 trampoline {:#x} → Thread+{:#x} → entrypoint {:#x}",
            trampoline, offset, resolved
        ));
        resolved
    } else {
        trampoline
    }
}

/// 发现并缓存所有 ART 内部桥接函数地址。
///
/// 策略:
/// 1. ClassLinker 扫描: 一次扫描提取 quick_generic_jni_trampoline、
///    quick_to_interpreter_bridge、quick_resolution_trampoline
/// 2. dlsym: GetNterpEntryPoint（调用它获取 nterp 入口）、DoCall 模板实例、
///    ConcurrentCopying::CopyingPhase
pub(super) unsafe fn find_art_bridge_functions(env: JniEnv, _ep_offset: usize) -> &'static ArtBridgeFunctions {
    ART_BRIDGE_FUNCTIONS.get_or_init(|| {
        output_message("[art bridge] 开始发现 ART 内部桥接函数...");

        // --- ClassLinker 扫描: 一次提取 4 个 trampoline ---
        let (jni_tramp, interp_bridge, resolution_tramp, imt_conflict) = find_classlinker_trampolines(env);

        output_message(&format!(
            "[art bridge] ClassLinker 结果: jni_tramp={:#x}, interp_bridge={:#x}, resolution_tramp={:#x}, imt_conflict={:#x}",
            jni_tramp, interp_bridge, resolution_tramp, imt_conflict
        ));

        // --- dlsym: Nterp 入口点 ---
        let nterp = find_nterp_entry_point();
        output_message(&format!("[art bridge] nterp_entry_point={:#x}", nterp));

        // --- dlsym: DoCall 模板实例 ---
        let do_calls = find_do_call_symbols();
        output_message(&format!("[art bridge] DoCall 实例数={}", do_calls.len()));
        for (i, addr) in do_calls.iter().enumerate() {
            output_message(&format!("[art bridge]   DoCall[{}]={:#x}", i, addr));
        }

        // --- dlsym: GC ConcurrentCopying::CopyingPhase ---
        let gc_phase = find_gc_copying_phase();
        output_message(&format!("[art bridge] gc_copying_phase={:#x}", gc_phase));

        // --- dlsym: Heap::CollectGarbageInternal ---
        let gc_collect = find_gc_collect_internal();
        output_message(&format!("[art bridge] gc_collect_internal={:#x}", gc_collect));

        // --- dlsym: Thread::RunFlipFunction ---
        let run_flip = find_run_flip_function();
        output_message(&format!("[art bridge] run_flip_function={:#x}", run_flip));

        // --- dlsym: ArtMethod::GetOatQuickMethodHeader ---
        let get_oat_header = find_get_oat_quick_method_header();
        output_message(&format!("[art bridge] get_oat_quick_method_header={:#x}", get_oat_header));

        // --- dlsym: FixupStaticTrampolines / MakeInitializedClassesVisiblyInitialized ---
        let fixup_static = find_fixup_static_trampolines();
        output_message(&format!("[art bridge] fixup_static_trampolines={:#x}", fixup_static));

        // --- dlsym: Thread::Current() (递归防护用) ---
        let thread_current = find_thread_current();
        output_message(&format!("[art bridge] thread_current={:#x}", thread_current));

        // --- dlsym: ArtMethod::PrettyMethod (NULL 指针崩溃防护) ---
        let pretty_method = find_pretty_method();
        output_message(&format!("[art bridge] pretty_method={:#x}", pretty_method));

        // --- 解析 trampoline → 真实 quick entrypoint ---
        let resolved_jni = resolve_quick_entrypoint_from_trampoline(jni_tramp, env);
        let resolved_interp = resolve_quick_entrypoint_from_trampoline(interp_bridge, env);
        let resolved_resolution = resolve_quick_entrypoint_from_trampoline(resolution_tramp, env);

        output_message(&format!(
            "[art bridge] resolved entrypoints: jni={:#x}, interp={:#x}, resolution={:#x}",
            resolved_jni, resolved_interp, resolved_resolution
        ));

        output_message("[art bridge] ART 桥接函数发现完成");

        ArtBridgeFunctions {
            quick_generic_jni_trampoline: jni_tramp,
            quick_to_interpreter_bridge: interp_bridge,
            quick_resolution_trampoline: resolution_tramp,
            quick_imt_conflict_trampoline: imt_conflict,
            nterp_entry_point: nterp,
            do_call_addrs: do_calls,
            gc_copying_phase: gc_phase,
            gc_collect_internal: gc_collect,
            run_flip_function: run_flip,
            get_oat_quick_method_header: get_oat_header,
            fixup_static_trampolines: fixup_static,
            thread_current,
            pretty_method,
            resolved_jni_entrypoint: resolved_jni,
            resolved_interpreter_bridge_entrypoint: resolved_interp,
            resolved_resolution_entrypoint: resolved_resolution,
        }
    })
}

/// 通过 ClassLinker 结构体扫描提取 3 个 ART trampoline 地址。
///
/// ClassLinker 布局 (Android 6+, 以 intern_table_ 为锚点):
///   intern_table_
///   quick_resolution_trampoline_            +1*8
///   quick_imt_conflict_trampoline_          +2*8
///   ... (delta 变量取决于 API 级别)
///   quick_generic_jni_trampoline_           +(delta)*8
///   quick_to_interpreter_bridge_trampoline_ +(delta+1)*8
///
/// 返回 (quick_generic_jni_trampoline, quick_to_interpreter_bridge, quick_resolution_trampoline, quick_imt_conflict_trampoline)
unsafe fn find_classlinker_trampolines(_env: JniEnv) -> (u64, u64, u64, u64) {
    // --- Strategy 1: dlsym (可能在某些 Android 构建中可用) ---
    // 注意: art_quick_* 符号通常是 LOCAL HIDDEN，dlsym 一般找不到
    // 通过 unrestricted API 查找（soinfo 摘除后 libc::dlsym 会崩溃）
    let jni_sym = crate::jsapi::module::libart_dlsym("art_quick_generic_jni_trampoline");
    let interp_sym = crate::jsapi::module::libart_dlsym("art_quick_to_interpreter_bridge");
    let resolution_sym = crate::jsapi::module::libart_dlsym("art_quick_resolution_trampoline");
    let imt_sym = crate::jsapi::module::libart_dlsym("art_quick_imt_conflict_trampoline");

    if !jni_sym.is_null() && !interp_sym.is_null() && !resolution_sym.is_null() {
        output_message("[art bridge] 全部通过 dlsym 发现");
        return (jni_sym as u64, interp_sym as u64, resolution_sym as u64, imt_sym as u64);
    }

    // --- Strategy 2: ClassLinker 扫描 (主要策略) ---
    // art_quick_* 是 LOCAL HIDDEN 符号，APEX namespace 限制下 dlsym 找不到
    // 必须通过 ClassLinker 结构体内存扫描获取
    output_message("[art bridge] dlsym 未能获取全部地址，尝试 ClassLinker 扫描...");

    let (runtime, java_vm_off) = match find_runtime_java_vm() {
        Some(v) => v,
        None => {
            output_message("[art bridge] ClassLinker 扫描: 无法获取 Runtime/java_vm_ 偏移");
            return (jni_sym as u64, interp_sym as u64, resolution_sym as u64, imt_sym as u64);
        }
    };

    output_message(&format!(
        "[art bridge] Runtime={:#x}, java_vm_ 在 Runtime+{:#x}", runtime, java_vm_off
    ));

    let api_level = get_android_api_level();
    let codename = get_android_codename();
    output_message(&format!("[art bridge] Android API level: {}, codename: '{}'", api_level, codename));

    let class_linker_candidates = compute_classlinker_candidates(java_vm_off);

    // find_runtime_java_vm 已经调用了 refresh_mem_regions()

    for &cl_off in &class_linker_candidates {
        let class_linker = safe_read_u64(runtime + cl_off as u64) & PAC_STRIP_MASK;
        if class_linker == 0 {
            continue;
        }

        let intern_table_off = cl_off - 8;
        let intern_table = safe_read_u64(runtime + intern_table_off as u64) & PAC_STRIP_MASK;
        if intern_table == 0 {
            continue;
        }

        output_message(&format!(
            "[art bridge] 候选: classLinker={:#x} (Runtime+{:#x}), internTable={:#x} (Runtime+{:#x})",
            class_linker, cl_off, intern_table, intern_table_off
        ));

        // 在 ClassLinker 中扫描 intern_table_ 指针作为锚点
        let cl_scan_start = 200usize;
        let cl_scan_end = cl_scan_start + 800;

        let mut intern_table_cl_offset: Option<usize> = None;
        for offset in (cl_scan_start..cl_scan_end).step_by(8) {
            let val = safe_read_u64(class_linker + offset as u64);
            let val_stripped = val & PAC_STRIP_MASK;
            if val_stripped == intern_table {
                intern_table_cl_offset = Some(offset);
                output_message(&format!(
                    "[art bridge] 找到 intern_table_ 在 ClassLinker+{:#x}", offset
                ));
                break;
            }
        }

        let it_off = match intern_table_cl_offset {
            Some(o) => o,
            None => {
                output_message("[art bridge] 此候选 ClassLinker 中未找到 intern_table_");
                continue;
            }
        };

        // 根据 API 级别计算 delta (intern_table_ 到 quick_generic_jni_trampoline_ 的字段数)
        let delta: usize = if api_level >= 30 || codename == "R" {
            6
        } else if api_level >= 29 {
            4
        } else if api_level >= 23 {
            3
        } else {
            5 // Android 5.x: portable_resolution/imt_conflict/to_interpreter trampolines
        };

        // 提取四个 trampoline 地址
        let jni_tramp_off = it_off + delta * 8;
        let interp_bridge_off = jni_tramp_off + 8;
        // imt_conflict trampoline: genericJni 前一个指针位置
        let imt_conflict_off = jni_tramp_off - 8;
        // resolution trampoline: 从 jni_tramp 反推（API 29+ 有额外字段，不再紧跟 intern_table）
        // API >= 23: resolution 在 jni_tramp 前 2 个位置
        // API < 23: resolution 在 jni_tramp 前 3 个位置（有 portable_resolution_trampoline_）
        let resolution_tramp_off = if api_level >= 23 {
            jni_tramp_off - 2 * 8
        } else {
            jni_tramp_off - 3 * 8
        };

        let jni_tramp = safe_read_u64(class_linker + jni_tramp_off as u64) & PAC_STRIP_MASK;
        let interp_bridge = safe_read_u64(class_linker + interp_bridge_off as u64) & PAC_STRIP_MASK;
        let resolution_tramp = safe_read_u64(class_linker + resolution_tramp_off as u64) & PAC_STRIP_MASK;
        let imt_conflict = safe_read_u64(class_linker + imt_conflict_off as u64) & PAC_STRIP_MASK;

        output_message(&format!(
            "[art bridge] ClassLinker: jni_tramp=ClassLinker+{:#x}={:#x}, interp=ClassLinker+{:#x}={:#x}, resolution=ClassLinker+{:#x}={:#x}, imt_conflict=ClassLinker+{:#x}={:#x}",
            jni_tramp_off, jni_tramp, interp_bridge_off, interp_bridge, resolution_tramp_off, resolution_tramp, imt_conflict_off, imt_conflict
        ));

        // 验证: 应为 libart.so 中的代码指针
        if jni_tramp != 0 && is_code_pointer(jni_tramp) {
            // 对可能通过 dlsym 找到的地址使用 dlsym 值，否则用 ClassLinker 值
            let final_jni = if jni_sym.is_null() { jni_tramp } else { jni_sym as u64 };
            let final_interp = if interp_bridge != 0 && is_code_pointer(interp_bridge) {
                interp_bridge
            } else if !interp_sym.is_null() {
                interp_sym as u64
            } else {
                0
            };
            let final_resolution = if resolution_tramp != 0 && is_code_pointer(resolution_tramp) {
                resolution_tramp
            } else if !resolution_sym.is_null() {
                resolution_sym as u64
            } else {
                0
            };
            let final_imt = if imt_conflict != 0 && is_code_pointer(imt_conflict) {
                imt_conflict
            } else if !imt_sym.is_null() {
                imt_sym as u64
            } else {
                0
            };

            return (final_jni, final_interp, final_resolution, final_imt);
        }
    }

    output_message("[art bridge] ClassLinker 扫描失败，返回 dlsym 结果（部分可能为0）");
    (jni_sym as u64, interp_sym as u64, resolution_sym as u64, imt_sym as u64)
}

/// 查找 Nterp 解释器入口点（Android 12+ / API 31+）
///
/// 策略 1: dlsym("art::interpreter::GetNterpEntryPoint") → 调用它获取入口点
/// 策略 2: dlsym("ExecuteNterpImpl") — 直接查找（通常 LOCAL HIDDEN，可能失败）
/// 返回 0 表示不可用（Android 11 及以下无 Nterp）
unsafe fn find_nterp_entry_point() -> u64 {
    // 策略 1: GetNterpEntryPoint 是一个返回入口点地址的函数
    let func_ptr = libart_dlsym("_ZN3art11interpreter18GetNterpEntryPointEv");
    if !func_ptr.is_null() {
        let get_nterp: unsafe extern "C" fn() -> u64 = std::mem::transmute(func_ptr);
        let ep = get_nterp();
        if ep != 0 {
            output_message(&format!(
                "[art bridge] Nterp 入口点通过 GetNterpEntryPoint() 获取: {:#x}", ep
            ));
            return ep;
        }
    }

    // 策略 2: ExecuteNterpImpl（LOCAL HIDDEN，通常无法通过 dlsym 访问）
    let func_ptr2 = libart_dlsym("ExecuteNterpImpl");
    if !func_ptr2.is_null() {
        output_message(&format!(
            "[art bridge] Nterp 入口点通过 ExecuteNterpImpl 获取: {:#x}", func_ptr2 as u64
        ));
        return func_ptr2 as u64;
    }

    output_message("[art bridge] Nterp 入口点不可用（Android 11 及以下）");
    0
}

/// 查找 art::interpreter::DoCall<> 模板实例（4个：bool×bool 组合）
///
/// Android 12 (API 23-33) 使用:
///   _ZN3art11interpreter6DoCallILb{0,1}ELb{0,1}EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE
unsafe fn find_do_call_symbols() -> Vec<u64> {
    let api_level = get_android_api_level();

    // 根据 API 级别构建符号名模式
    let symbols: Vec<String> = if api_level <= 22 {
        // Android 5.x: ArtMethod 在 mirror 命名空间
        let mut syms = Vec::new();
        for b0 in &["0", "1"] {
            for b1 in &["0", "1"] {
                syms.push(format!(
                    "_ZN3art11interpreter6DoCallILb{}ELb{}EEEbPNS_6mirror9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE",
                    b0, b1
                ));
            }
        }
        syms
    } else if api_level <= 33 {
        // Android 6-13: 标准签名
        let mut syms = Vec::new();
        for b0 in &["0", "1"] {
            for b1 in &["0", "1"] {
                syms.push(format!(
                    "_ZN3art11interpreter6DoCallILb{}ELb{}EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE",
                    b0, b1
                ));
            }
        }
        syms
    } else {
        // Android 14+: 单 bool 模板参数
        let mut syms = Vec::new();
        for b0 in &["0", "1"] {
            syms.push(format!(
                "_ZN3art11interpreter6DoCallILb{}EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtbPNS_6JValueE",
                b0
            ));
        }
        syms
    };

    let mut addrs = Vec::new();
    for sym_str in &symbols {
        let addr = libart_dlsym(sym_str);
        if !addr.is_null() {
            addrs.push(addr as u64);
        }
    }

    addrs
}

/// 清空 JIT 代码缓存: 调用 JitCodeCache::InvalidateAllMethods()
///
/// 首次 hook 时调用一次，使所有已 JIT 编译的代码失效:
/// - 已内联被 hook 方法的调用者代码失效 → 退回解释器
/// - 重新 JIT 时不再内联被 hook 方法 (kAccSingleImplementation 已清除)
///
/// best-effort: 符号未找到或指针无效时仅 log 警告，不阻断 hook 流程。
pub(super) unsafe fn try_invalidate_jit_cache() {
    // 查找 InvalidateAllMethods 符号
    let func_ptr = libart_dlsym("_ZN3art3jit12JitCodeCache21InvalidateAllMethodsEv");

    if func_ptr.is_null() {
        output_message("[jit cache] InvalidateAllMethods 符号未找到，跳过 JIT 缓存清空");
        return;
    }

    // 从 JavaVM → Runtime → jit_code_cache_ 导航获取 JitCodeCache*
    let runtime = match get_runtime_addr() {
        Some(r) => r,
        None => {
            output_message("[jit cache] 无法获取 Runtime 地址，跳过 JIT 缓存清空");
            return;
        }
    };

    // 从 Runtime 获取 jit_code_cache_:
    // 尝试 dlsym Runtime::instance_ 获取更可靠的路径
    let instance_ptr = crate::jsapi::module::libart_dlsym("_ZN3art7Runtime9instance_E");

    let runtime_addr = if !instance_ptr.is_null() {
        let rt = *(instance_ptr as *const u64);
        let rt_stripped = rt & PAC_STRIP_MASK;
        if rt_stripped != 0 { rt_stripped } else { runtime }
    } else {
        runtime
    };

    // 扫描 Runtime 查找 jit_ (Jit*) 指针
    // jit_ 通常在 Runtime 布局的后半部分
    // 策略: 通过 dlsym 查找 Jit::code_cache_ 的偏移
    // 简化方案: 直接用 dlsym 查找 jit_code_cache_ 全局或从 Runtime 扫描

    // 方案 A: 尝试 Runtime::jit_code_cache_ 直接访问
    // Runtime 的 jit_code_cache_ 字段可以通过扫描找到
    // 但更可靠的方式是: 扫描 Runtime 找到 Jit* (非空且是合理的堆指针)
    // 然后从 Jit 中取 code_cache_ (通常在 Jit+8 或 Jit+16)

    // 方案 B (更简单): 通过 dlsym 获取 jit_code_cache_ 成员偏移
    // 实际上最简单的方案: 扫描 Runtime 寻找指向合法 JitCodeCache 的指针

    // 使用 Jit::GetCodeCache() 如果可用
    let get_code_cache_ptr = crate::jsapi::module::libart_dlsym(
        "_ZNK3art3jit3Jit12GetCodeCacheEv"
    );

    if !get_code_cache_ptr.is_null() {
        // 需要 Jit* this — 从 Runtime 获取
        // Runtime::jit_ 指针扫描
        // jit_ 通常在 Runtime 中较后的位置 (offset 600-900)
        refresh_mem_regions();
        let scan_start = 500usize;
        let scan_end = 1200usize;

        for offset in (scan_start..scan_end).step_by(8) {
            let candidate = safe_read_u64(runtime_addr + offset as u64);
            let candidate_stripped = candidate & PAC_STRIP_MASK;

            // 跳过空指针和非堆地址
            if candidate_stripped == 0 || candidate_stripped < 0x7000_0000 {
                continue;
            }

            // 尝试作为 Jit* 调用 GetCodeCache()
            // GetCodeCache 是 const 方法: JitCodeCache* GetCodeCache() const
            type GetCodeCacheFn = unsafe extern "C" fn(this: u64) -> u64;
            let get_code_cache: GetCodeCacheFn = std::mem::transmute(get_code_cache_ptr);

            // 安全检查: 确保 candidate 看起来像合理的对象指针
            // 读取前 8 字节看是否为合理值
            let first_word = safe_read_u64(candidate_stripped);
            if first_word == 0 {
                continue;
            }

            let code_cache = get_code_cache(candidate_stripped);
            let code_cache_stripped = code_cache & PAC_STRIP_MASK;
            if code_cache_stripped != 0 && code_cache_stripped > 0x7000_0000 {
                // 找到了 JitCodeCache*，调用 InvalidateAllMethods
                type InvalidateAllFn = unsafe extern "C" fn(this: u64);
                let invalidate: InvalidateAllFn = std::mem::transmute(func_ptr);
                invalidate(code_cache_stripped);
                output_message(&format!(
                    "[jit cache] InvalidateAllMethods 调用成功: JitCodeCache={:#x} (Runtime+{:#x})",
                    code_cache_stripped, offset
                ));
                return;
            }
        }

        output_message("[jit cache] 未找到 Jit* 指针，尝试直接扫描 JitCodeCache...");
    }

    // 方案 C: 直接扫描 Runtime 找 jit_code_cache_ 指针
    // jit_code_cache_ 是一个独立字段，通常紧跟 jit_ 之后
    // 这里我们放弃精确查找，仅记录警告
    output_message("[jit cache] JIT 缓存清空跳过: 无法定位 JitCodeCache 指针");
}

/// 查找 GC ConcurrentCopying::CopyingPhase 或 MarkingPhase 符号
///
/// API > 28: CopyingPhase
/// API 23-28: MarkingPhase
unsafe fn find_gc_copying_phase() -> u64 {
    let api_level = get_android_api_level();

    let sym_name = if api_level > 28 {
        "_ZN3art2gc9collector17ConcurrentCopying12CopyingPhaseEv"
    } else if api_level > 22 {
        "_ZN3art2gc9collector17ConcurrentCopying12MarkingPhaseEv"
    } else {
        return 0; // Android 5.x 不使用 ConcurrentCopying
    };

    libart_dlsym(sym_name) as u64
}

/// 查找 Heap::CollectGarbageInternal 符号
///
/// 主 GC 入口点，GC 完成后需要同步 replacement 方法。
/// 符号签名因 Android 版本不同而异。
unsafe fn find_gc_collect_internal() -> u64 {
    let candidates = [
        // Android 12+ (API 31+): 5-arg overload (extra uint32_t param)
        "_ZN3art2gc4Heap22CollectGarbageInternalENS0_9collector6GcTypeENS0_7GcCauseEbj",
        // Android 12+ (API 31+): 4-arg overload
        "_ZN3art2gc4Heap22CollectGarbageInternalENS0_9collector6GcTypeENS0_7GcCauseEb",
        // Android 10-11 (API 29-30)
        "_ZN3art2gc4Heap22CollectGarbageInternalENS0_9collector6GcTypeENS0_7GcCauseEbPKNS0_9collector14GarbageCollectorE",
        // Older variants
        "_ZN3art2gc4Heap22CollectGarbageInternalENS0_13GcCauseEb",
    ];

    dlsym_first_match(&candidates)
}

/// 查找 Thread::RunFlipFunction 符号
///
/// 线程翻转期间需要同步 replacement 方法（moving GC 相关）。
unsafe fn find_run_flip_function() -> u64 {
    let candidates = [
        // Android 12+ (API 31+): 带 bool 参数
        "_ZN3art6Thread15RunFlipFunctionEPS0_b",
        // Android 10-11 (API 29-30)
        "_ZN3art6Thread15RunFlipFunctionEPS0_",
    ];

    dlsym_first_match(&candidates)
}

/// 查找 ArtMethod::GetOatQuickMethodHeader 符号
///
/// ART 通过此函数查找方法的 OAT 编译代码头。对 replacement method（堆分配），
/// 此调用可能返回错误结果或崩溃。需要拦截并对 replacement 返回 NULL。
unsafe fn find_get_oat_quick_method_header() -> u64 {
    let candidates = [
        "_ZN3art9ArtMethod23GetOatQuickMethodHeaderEm",
        // 某些 Android 版本使用 uintptr_t
        "_ZN3art9ArtMethod23GetOatQuickMethodHeaderEj",
    ];

    dlsym_first_match(&candidates)
}

/// 查找 FixupStaticTrampolines 或 MakeInitializedClassesVisiblyInitialized 符号
///
/// 当类完成延迟初始化时，ART 可能更新静态方法的 quickCode，
/// 从 resolution_trampoline 变为编译代码，绕过 hook。
unsafe fn find_fixup_static_trampolines() -> u64 {
    let candidates = [
        // Android 12+ (API 31+): MakeInitializedClassesVisiblyInitialized (40 chars)
        "_ZN3art11ClassLinker40MakeInitializedClassesVisiblyInitializedEPNS_6ThreadEb",
        // Android 8-11: FixupStaticTrampolines with Thread* param (ObjPtr 版本)
        "_ZN3art11ClassLinker22FixupStaticTrampolinesEPNS_6ThreadENS_6ObjPtrINS_6mirror5ClassEEE",
        // Android 8-11: FixupStaticTrampolines (ObjPtr 版本, no Thread*)
        "_ZN3art11ClassLinker22FixupStaticTrampolinesEPNS_6ObjPtrINS_6mirror5ClassEEE",
        // Android 7: FixupStaticTrampolines (raw pointer 版本)
        "_ZN3art11ClassLinker22FixupStaticTrampolinesEPNS_6mirror5ClassE",
    ];

    dlsym_first_match(&candidates)
}

/// 查找 art::Thread::Current() 函数地址
///
/// 用于递归防护: 在 on_do_call_enter 中获取当前线程的 Thread*,
/// 读取 ManagedStack 判断是否处于 callOriginal 递归中。
unsafe fn find_thread_current() -> u64 {
    libart_dlsym("_ZN3art6Thread7CurrentEv") as u64
}

/// 查找 ArtMethod::PrettyMethod 函数地址
///
/// 对标 Frida fixupArtQuickDeliverExceptionBug: 当 method==NULL 时
/// PrettyMethod 会崩溃。Hook 此函数替换 NULL 为上次见到的非空 method。
/// 优先成员函数版本，fallback 到静态函数版本。
unsafe fn find_pretty_method() -> u64 {
    // 成员函数版本: ArtMethod::PrettyMethod(bool)
    let addr = libart_dlsym("_ZN3art9ArtMethod12PrettyMethodEb");
    if !addr.is_null() {
        return addr as u64;
    }
    // 静态函数版本: PrettyMethod(ArtMethod*, bool)
    let addr = libart_dlsym("_ZN3art12PrettyMethodEPNS_9ArtMethodEb");
    addr as u64
}

// ============================================================================
// ART entrypoint classification helpers
// ============================================================================

/// Check if an address is an ART shared entrypoint (stub/bridge/nterp)
/// or resides inside libart.so.
///
/// Returns true if the address is:
/// - 0 (null)
/// - One of the known shared stubs (jni_trampoline, interpreter_bridge, resolution, nterp)
/// - Inside libart.so (e.g. other ART internal trampolines)
///
/// Compiled methods (AOT/JIT) that have independent code OUTSIDE libart.so return false.
pub(super) fn is_art_quick_entrypoint(addr: u64, bridge: &ArtBridgeFunctions) -> bool {
    if addr == 0 {
        return true;
    }
    // ClassLinker trampoline 地址比较（对标 Frida isArtQuickEntrypoint）
    if addr == bridge.quick_generic_jni_trampoline
        || addr == bridge.quick_to_interpreter_bridge
        || addr == bridge.quick_resolution_trampoline
        || addr == bridge.quick_imt_conflict_trampoline
        || addr == bridge.nterp_entry_point
    {
        return true;
    }
    // Thread TLS 中的真实 entrypoint 比较（trampoline 解析结果，0 表示无效跳过）
    if (bridge.resolved_jni_entrypoint != 0 && addr == bridge.resolved_jni_entrypoint)
        || (bridge.resolved_interpreter_bridge_entrypoint != 0 && addr == bridge.resolved_interpreter_bridge_entrypoint)
        || (bridge.resolved_resolution_entrypoint != 0 && addr == bridge.resolved_resolution_entrypoint)
    {
        return true;
    }
    // dladdr check: is this address in libart.so?
    is_in_libart(addr)
}

// ============================================================================
// ArtMethod resolution
// ============================================================================

/// Resolve a Java method to its ArtMethod* address.
/// Returns (art_method_ptr, is_static).
/// When `force_static` is true, skips GetMethodID and goes straight to GetStaticMethodID.
pub(super) fn resolve_art_method(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    signature: &str,
    force_static: bool,
) -> Result<(u64, bool), String> {
    let c_method = CString::new(method_name).map_err(|_| "invalid method name")?;
    let c_sig = CString::new(signature).map_err(|_| "invalid signature")?;

    unsafe {
        let cls = find_class_safe(env, class_name);

        if cls.is_null() {
            // Defensive: ensure no pending exception leaks to caller
            jni_check_exc(env);
            return Err(format!("FindClass('{}') failed", class_name));
        }

        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

        // Try GetMethodID (instance method first), unless force_static
        if !force_static {
            let get_method_id: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);

            let method_id = get_method_id(env, cls, c_method.as_ptr(), c_sig.as_ptr());
            output_message(&format!(
                "[resolve_art_method] cls={:#x}, GetMethodID({}.{}{})={:#x}",
                cls as u64, class_name, method_name, signature, method_id as u64
            ));

            if !method_id.is_null() && !jni_check_exc(env) {
                // Decode BEFORE deleting cls (ToReflectedMethod needs cls)
                let art_method = decode_method_id(env, cls, method_id as u64, false);
                delete_local_ref(env, cls);
                return Ok((art_method, false));
            }

            // Clear exception from GetMethodID failure
            jni_check_exc(env);
        }

        // Try GetStaticMethodID
        let get_static_method_id: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);

        let method_id = get_static_method_id(env, cls, c_method.as_ptr(), c_sig.as_ptr());

        if !method_id.is_null() && !jni_check_exc(env) {
            // Decode BEFORE deleting cls (ToReflectedMethod needs cls)
            let art_method = decode_method_id(env, cls, method_id as u64, true);
            delete_local_ref(env, cls);
            return Ok((art_method, true));
        }

        jni_check_exc(env);

        // Cleanup
        delete_local_ref(env, cls);

        Err(format!(
            "method not found: {}.{}{}",
            class_name, method_name, signature
        ))
    }
}

/// Read the entry_point_from_quick_compiled_code_ from ArtMethod
pub(super) unsafe fn read_entry_point(art_method: u64, offset: usize) -> u64 {
    let ptr = (art_method as usize + offset) as *const u64;
    std::ptr::read_volatile(ptr)
}

// ============================================================================
// Field cache — pre-enumerated at hook time (safe thread), used from callbacks
// ============================================================================

pub(super) struct CachedFieldInfo {
    pub(super) jni_sig: String,
    pub(super) field_id: *mut std::ffi::c_void, // jfieldID — stable across threads
    pub(super) is_static: bool,
}

unsafe impl Send for CachedFieldInfo {}
unsafe impl Sync for CachedFieldInfo {}

/// Cached field info per class: className → (fieldName → CachedFieldInfo)
pub(super) static FIELD_CACHE: Mutex<Option<HashMap<String, HashMap<String, CachedFieldInfo>>>> =
    Mutex::new(None);

/// Enumerate and cache all fields (instance + static) for a class (including inherited).
/// Must be called from a safe thread (not a hook callback).
pub(super) unsafe fn cache_fields_for_class(
    env: JniEnv,
    class_name: &str,
) {
    // Initialize cache if needed
    {
        let mut guard = FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            *guard = Some(HashMap::new());
        }
        // Skip if already cached
        if guard.as_ref().unwrap().contains_key(class_name) {
            return;
        }
    }

    // Enumerate fields using JNI reflection (safe from init thread)
    let fields = match enumerate_class_fields(env, class_name) {
        Ok(f) => f,
        Err(_e) => return,
    };

    // Resolve field IDs and store in cache
    let get_field_id: GetFieldIdFn = jni_fn!(env, GetFieldIdFn, JNI_GET_FIELD_ID);
    let get_static_field_id: GetStaticFieldIdFn = jni_fn!(env, GetStaticFieldIdFn, JNI_GET_STATIC_FIELD_ID);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let cls = find_class_safe(env, class_name);
    if cls.is_null() {
        return;
    }

    let mut field_map = HashMap::new();
    for (name, type_name, is_static) in &fields {
        let jni_sig = java_type_to_jni(type_name);
        let c_name = match CString::new(name.as_str()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let c_sig = match CString::new(jni_sig.as_str()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // IMPORTANT: Always clear pending exceptions before calling Get[Static]FieldID.
        // GetFieldID will abort (SIGABRT) if there's already a pending exception.
        jni_check_exc(env);
        let fid = if *is_static {
            get_static_field_id(env, cls, c_name.as_ptr(), c_sig.as_ptr())
        } else {
            get_field_id(env, cls, c_name.as_ptr(), c_sig.as_ptr())
        };
        if fid.is_null() {
            jni_check_exc(env); // Clear exception from failed GetFieldID
            continue;
        }
        field_map.insert(
            name.clone(),
            CachedFieldInfo {
                jni_sig,
                field_id: fid,
                is_static: *is_static,
            },
        );
    }

    delete_local_ref(env, cls);

    let mut guard = FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(cache) = guard.as_mut() {
        cache.insert(class_name.to_string(), field_map);
    }
}

/// Enumerate fields of a class and all its superclasses via JNI reflection.
/// Returns Vec<(fieldName, typeName, is_static)>.
unsafe fn enumerate_class_fields(
    env: JniEnv,
    class_name: &str,
) -> Result<Vec<(String, String, bool)>, String> {
    use std::ffi::CStr;

    let reflect = REFLECT_IDS.get().ok_or("reflection IDs not cached")?;

    let find_class: FindClassFn = jni_fn!(env, FindClassFn, JNI_FIND_CLASS);
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let call_int: CallIntMethodAFn = jni_fn!(env, CallIntMethodAFn, JNI_CALL_INT_METHOD_A);
    let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
    let rel_str: ReleaseStringUtfCharsFn = jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);
    let get_arr_len: GetArrayLengthFn = jni_fn!(env, GetArrayLengthFn, JNI_GET_ARRAY_LENGTH);
    let get_arr_elem: GetObjectArrayElementFn =
        jni_fn!(env, GetObjectArrayElementFn, JNI_GET_OBJECT_ARRAY_ELEMENT);
    let push_frame: PushLocalFrameFn = jni_fn!(env, PushLocalFrameFn, JNI_PUSH_LOCAL_FRAME);
    let pop_frame: PopLocalFrameFn = jni_fn!(env, PopLocalFrameFn, JNI_POP_LOCAL_FRAME);

    if push_frame(env, 512) < 0 {
        return Err("PushLocalFrame failed".to_string());
    }

    let cls = find_class_safe(env, class_name);
    if cls.is_null() {
        pop_frame(env, std::ptr::null_mut());
        return Err("FindClass failed".to_string());
    }

    // Get reflection method IDs (system classes — FindClass is fine)
    let c_class_cls = CString::new("java/lang/Class").unwrap();
    let c_field_cls = CString::new("java/lang/reflect/Field").unwrap();
    let class_cls = find_class(env, c_class_cls.as_ptr());
    let field_cls = find_class(env, c_field_cls.as_ptr());

    let c_get_fields = CString::new("getFields").unwrap();
    let c_get_fields_sig = CString::new("()[Ljava/lang/reflect/Field;").unwrap();
    let c_get_declared_fields = CString::new("getDeclaredFields").unwrap();
    let c_get_name = CString::new("getName").unwrap();
    let c_str_sig = CString::new("()Ljava/lang/String;").unwrap();
    let c_get_type = CString::new("getType").unwrap();
    let c_get_type_sig = CString::new("()Ljava/lang/Class;").unwrap();
    let c_get_mods = CString::new("getModifiers").unwrap();
    let c_get_mods_sig = CString::new("()I").unwrap();

    let get_fields_mid = get_mid(env, class_cls, c_get_fields.as_ptr(), c_get_fields_sig.as_ptr());
    let get_declared_fields_mid = get_mid(env, class_cls, c_get_declared_fields.as_ptr(), c_get_fields_sig.as_ptr());
    let field_get_name_mid = get_mid(env, field_cls, c_get_name.as_ptr(), c_str_sig.as_ptr());
    let field_get_type_mid = get_mid(env, field_cls, c_get_type.as_ptr(), c_get_type_sig.as_ptr());
    let field_get_mods_mid = get_mid(env, field_cls, c_get_mods.as_ptr(), c_get_mods_sig.as_ptr());

    jni_check_exc(env);

    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Helper: extract fields from a Field[] array
    let mut extract_fields = |arr: *mut std::ffi::c_void| {
        if arr.is_null() { return; }
        let len = get_arr_len(env, arr);
        for i in 0..len {
            let field = get_arr_elem(env, arr, i);
            if field.is_null() { continue; }

            // getName()
            let name_jstr = call_obj(env, field, field_get_name_mid, std::ptr::null());
            if name_jstr.is_null() { continue; }
            let name_chars = get_str(env, name_jstr, std::ptr::null_mut());
            let name = CStr::from_ptr(name_chars).to_string_lossy().to_string();
            rel_str(env, name_jstr, name_chars);

            if seen.contains(&name) { continue; }

            // getModifiers() — check for static (0x0008)
            let modifiers = if !field_get_mods_mid.is_null() {
                call_int(env, field, field_get_mods_mid, std::ptr::null())
            } else {
                0
            };
            let is_static = (modifiers & 0x0008) != 0;

            // getType().getName()
            let type_cls_obj = call_obj(env, field, field_get_type_mid, std::ptr::null());
            if type_cls_obj.is_null() { continue; }
            let type_name_jstr = call_obj(env, type_cls_obj, reflect.class_get_name_mid, std::ptr::null());
            if type_name_jstr.is_null() { continue; }
            let tc = get_str(env, type_name_jstr, std::ptr::null_mut());
            let type_name = CStr::from_ptr(tc).to_string_lossy().to_string();
            rel_str(env, type_name_jstr, tc);

            seen.insert(name.clone());
            results.push((name, type_name, is_static));
        }
    };

    // Walk the entire class hierarchy: getDeclaredFields() on each class
    // to capture protected/private inherited fields (e.g. mBase in ContextWrapper).
    {
        let c_get_superclass = CString::new("getSuperclass").unwrap();
        let c_get_superclass_sig = CString::new("()Ljava/lang/Class;").unwrap();
        let get_superclass_mid = get_mid(
            env, class_cls,
            c_get_superclass.as_ptr(), c_get_superclass_sig.as_ptr(),
        );

        let mut current_cls = cls;
        loop {
            if current_cls.is_null() { break; }

            // getDeclaredFields() on current class
            if !get_declared_fields_mid.is_null() {
                let arr = call_obj(env, current_cls, get_declared_fields_mid, std::ptr::null());
                if jni_check_exc(env) { /* skip */ }
                else { extract_fields(arr); }
            }

            // Walk to superclass
            if get_superclass_mid.is_null() { break; }
            let super_cls = call_obj(env, current_cls, get_superclass_mid, std::ptr::null());
            if jni_check_exc(env) || super_cls.is_null() { break; }
            current_cls = super_cls;
        }
    }

    // getFields() — all public inherited fields (catches interface constants, etc.)
    if !get_fields_mid.is_null() {
        let arr = call_obj(env, cls, get_fields_mid, std::ptr::null());
        if jni_check_exc(env) { /* skip */ }
        else { extract_fields(arr); }
    }

    pop_frame(env, std::ptr::null_mut());
    Ok(results)
}

// ============================================================================
// Instrumentation 偏移探测 — 对标 Frida tryDetectInstrumentationOffset/Pointer
// ============================================================================

/// Instrumentation 偏移规格
pub(super) struct InstrumentationSpec {
    /// Runtime.instrumentation_ 在 Runtime 结构体中的偏移
    pub runtime_instrumentation_offset: usize,
    /// Instrumentation.force_interpret_only_ 在 Instrumentation 结构体中的偏移 (固定=4)
    pub force_interpret_only_offset: usize,
    /// Instrumentation.deoptimization_enabled_ 偏移 (按 API level 查表, 可能不可用)
    pub deoptimization_enabled_offset: Option<usize>,
    /// true = 指针模式 (APEX >= 360_000_000), false = 嵌入模式
    pub is_pointer_mode: bool,
}

/// 缓存的 Instrumentation 偏移探测结果
static INSTRUMENTATION_SPEC: OnceLock<Option<InstrumentationSpec>> = OnceLock::new();

/// 获取缓存的 Instrumentation 偏移规格（首次调用时探测）
pub(super) fn get_instrumentation_spec() -> Option<&'static InstrumentationSpec> {
    INSTRUMENTATION_SPEC.get_or_init(|| probe_instrumentation_spec()).as_ref()
}

/// 按 API level 返回 Instrumentation.deoptimization_enabled_ 偏移 (64-bit ARM64)
/// 对标 Frida android.js 中的 deoptimizationEnabled 查找表 (pointerSize=8)
///
/// - API 21-31: 与 Frida 表一致的硬编码值
/// - API 32 (Android 12L): Instrumentation 结构体与 API 31 相同，偏移不变
/// - API 33+ (Android 13+): AOSP commit ba8600819d 将 EnableDeoptimization 变为 nop，
///   deoptimization_enabled_ 字段已无实际作用。Frida 在 API 32+ 也没有提供偏移，
///   而是通过检查 EnableDeoptimization 符号是否存在来决定是否使用该字段。
///   这里对 API 33+ 返回 None，调用方应检查 EnableDeoptimization 符号可用性。
fn get_deoptimization_enabled_offset() -> Option<usize> {
    match get_android_api_level() {
        21 | 22 => Some(224),
        23 => Some(296),
        24 | 25 => Some(344),
        26 | 27 => Some(352),
        28 => Some(392),
        29 => Some(328),
        30 | 31 | 32 => Some(336),
        // API 33+: deoptimization_enabled_ 已无实际作用，返回 None
        _ => None,
    }
}

/// 反汇编 art::Runtime::DeoptimizeBootImage 提取 Runtime.instrumentation_ 的偏移。
///
/// 对标 Frida tryDetectInstrumentationOffset / tryDetectInstrumentationPointer:
/// - 嵌入模式 (APEX < 360_000_000): 查找 ADD Xd, Xn, #imm 指令
/// - 指针模式 (APEX >= 360_000_000): 查找 LDR Xt, [Xn, #imm] 指令
///
/// 仅支持 ARM64。
pub(super) fn probe_instrumentation_spec() -> Option<InstrumentationSpec> {
    // Step 1: dlsym 查找 art::Runtime::DeoptimizeBootImage
    let sym = unsafe { crate::jsapi::module::libart_dlsym("_ZN3art7Runtime19DeoptimizeBootImageEv") };
    if sym.is_null() {
        output_message("[instrumentation] DeoptimizeBootImage 符号未找到");
        return None;
    }

    // Step 2: 根据 APEX 版本判断解析模式
    let apex_version = get_art_apex_version();
    let is_pointer_mode = apex_version >= 360_000_000;
    let deopt_offset = get_deoptimization_enabled_offset();

    output_message(&format!(
        "[instrumentation] DeoptimizeBootImage={:#x}, APEX={}, 模式={}",
        sym as u64, apex_version, if is_pointer_mode { "指针" } else { "嵌入" }
    ));

    // Step 3: 扫描前 30 条 ARM64 指令（每条 4 字节）
    let func_addr = sym as u64;
    for i in 0..30u64 {
        let insn_addr = func_addr + i * 4;
        let insn = unsafe { *(insn_addr as *const u32) };

        if is_pointer_mode {
            // 指针模式: 查找 LDR Xt, [Xn, #imm] (64-bit unsigned offset)
            // 编码: 1111 1001 01ii iiii iiii iinn nnnt tttt = 0xF940_0000
            // mask: 0xFFC0_0000
            if (insn & 0xFFC0_0000) == 0xF940_0000 {
                let rt = insn & 0x1F;
                let rn = (insn >> 5) & 0x1F;
                let imm12 = ((insn >> 10) & 0xFFF) as usize;
                let offset = imm12 * 8; // LDR X 的 imm12 按 8 缩放

                // 排除 x0 作为目标（Frida: ops[0].value === 'x0' → skip）
                // 基址必须是 x0（this 指针）
                if rt == 0 || rn != 0 {
                    continue;
                }

                if offset >= 0x100 && offset <= 0x400 {
                    output_message(&format!(
                        "[instrumentation] 指针模式: LDR x{}, [x{}, #{}]", rt, rn, offset
                    ));
                    return Some(InstrumentationSpec {
                        runtime_instrumentation_offset: offset,
                        force_interpret_only_offset: 4,
                        deoptimization_enabled_offset: deopt_offset,
                        is_pointer_mode: true,
                    });
                }
            }
        } else {
            // 嵌入模式: 查找 ADD Xd, Xn, #imm (64-bit)
            // SF=1, op=0, S=0 → 1001 0001
            // shift=00: mask 0xFF80_0000, value 0x9100_0000
            // shift=01: mask 0xFF80_0000, value 0x9140_0000
            let masked = insn & 0xFF80_0000;
            if masked == 0x9100_0000 || masked == 0x9140_0000 {
                let rd = insn & 0x1F;
                let rn = (insn >> 5) & 0x1F;
                let imm12 = ((insn >> 10) & 0xFFF) as usize;
                let shift = ((insn >> 22) & 0x3) as usize;
                let offset = if shift == 1 { imm12 << 12 } else { imm12 };

                // 排除 sp (x31) 操作
                if rd == 31 || rn == 31 {
                    continue;
                }

                if offset >= 0x100 && offset <= 0x400 {
                    output_message(&format!(
                        "[instrumentation] 嵌入模式: ADD x{}, x{}, #{}", rd, rn, offset
                    ));
                    return Some(InstrumentationSpec {
                        runtime_instrumentation_offset: offset,
                        force_interpret_only_offset: 4,
                        deoptimization_enabled_offset: deopt_offset,
                        is_pointer_mode: false,
                    });
                }
            }
        }
    }

    output_message("[instrumentation] 未找到 Instrumentation 偏移");
    None
}

// ============================================================================
// Runtime/JavaVM 共享辅助函数
// ============================================================================

/// 从 JNI_STATE 获取 Runtime* 和 java_vm_ 在 Runtime 中的偏移。
///
/// 扫描 Runtime 结构体查找 JavaVM* 指针位置。
/// 返回 (runtime_addr, java_vm_offset)，如果获取失败返回 None。
pub(super) unsafe fn find_runtime_java_vm() -> Option<(u64, usize)> {
    let vm_ptr = {
        let guard = JNI_STATE.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(state) => state.vm,
            None => return None,
        }
    };

    let runtime = get_runtime_addr()?;

    refresh_mem_regions();

    let vm_addr_stripped = (vm_ptr as u64) & PAC_STRIP_MASK;
    let scan_start = 384usize;
    let scan_end = scan_start + 800;

    for offset in (scan_start..scan_end).step_by(8) {
        let val = safe_read_u64(runtime + offset as u64);
        let val_stripped = val & PAC_STRIP_MASK;
        if val_stripped == vm_addr_stripped {
            return Some((runtime, offset));
        }
    }

    None
}

// ============================================================================
// ArtRuntimeSpec — Runtime 内部偏移 (对标 Frida getArtRuntimeSpec)
// ============================================================================

/// ART Runtime 内部关键偏移
pub(super) struct ArtRuntimeSpec {
    /// Heap* 偏移
    pub heap_offset: usize,
    /// ThreadList* 偏移
    pub thread_list_offset: usize,
    /// InternTable* 偏移
    pub intern_table_offset: usize,
    /// ClassLinker* 偏移
    pub class_linker_offset: usize,
    /// JniIdManager* 偏移 (API 30+, None for older)
    pub jni_id_manager_offset: Option<usize>,
    /// Runtime 地址
    pub runtime_addr: u64,
}

static ART_RUNTIME_SPEC: OnceLock<Option<ArtRuntimeSpec>> = OnceLock::new();

/// 获取缓存的 ArtRuntimeSpec（首次调用时探测）
pub(super) fn get_art_runtime_spec() -> Option<&'static ArtRuntimeSpec> {
    ART_RUNTIME_SPEC.get_or_init(|| unsafe { probe_art_runtime_spec() }).as_ref()
}

/// 验证 classLinker 偏移是否正确（对标 Frida tryGetArtClassLinkerSpec）
///
/// 在 ClassLinker 结构体内部扫描 InternTable* 指针。
/// 如果找到匹配，说明 classLinkerOffset 正确。
unsafe fn verify_class_linker_offset(
    runtime: u64,
    class_linker_offset: usize,
    intern_table_offset: usize,
) -> bool {
    const PTR_SIZE: usize = 8;

    let cl_ptr = safe_read_u64(runtime + class_linker_offset as u64) & PAC_STRIP_MASK;
    let it_ptr = safe_read_u64(runtime + intern_table_offset as u64) & PAC_STRIP_MASK;

    if cl_ptr == 0 || it_ptr == 0 {
        output_message(&format!(
            "[art runtime] 交叉验证跳过: classLinker*={:#x}, internTable*={:#x}",
            cl_ptr, it_ptr
        ));
        return false;
    }

    // 在 ClassLinker 内部扫描 InternTable* 指针（对标 Frida: startOffset=200, range=100*PTR_SIZE）
    let scan_start = 200usize;
    let scan_end = scan_start + 800;

    for offset in (scan_start..scan_end).step_by(PTR_SIZE) {
        let val = safe_read_u64(cl_ptr + offset as u64) & PAC_STRIP_MASK;
        if val == it_ptr {
            output_message(&format!(
                "[art runtime] 交叉验证通过: 在 ClassLinker+{:#x} 找到 InternTable*={:#x}",
                offset, it_ptr
            ));
            return true;
        }
    }

    output_message(&format!(
        "[art runtime] 交叉验证失败: ClassLinker({:#x}) 中未找到 InternTable*({:#x})",
        cl_ptr, it_ptr
    ));
    false
}

/// 探测 ART Runtime 内部偏移（对标 Frida getArtRuntimeSpec / android.js:649-676）
///
/// 复用 find_runtime_java_vm 获取 Runtime 地址和 java_vm_ 偏移，
/// 然后根据 API level 计算 classLinker_, internTable_, threadList_, heap_ 偏移。
unsafe fn probe_art_runtime_spec() -> Option<ArtRuntimeSpec> {
    let (runtime, java_vm_off) = match find_runtime_java_vm() {
        Some(v) => v,
        None => {
            output_message("[art runtime] 无法获取 Runtime/java_vm_ 偏移");
            return None;
        }
    };

    let api_level = get_android_api_level();
    let is_34_equiv = is_api_level_34_or_apex_equivalent();

    const PTR_SIZE: usize = 8;

    let candidates = compute_classlinker_candidates(java_vm_off);

    // 对标 Frida tryGetArtClassLinkerSpec: 对每个候选进行 ClassLinker 内部结构验证
    let mut class_linker_offset: Option<usize> = None;
    for &candidate in &candidates {
        let intern_table_candidate = candidate - PTR_SIZE;
        if verify_class_linker_offset(runtime, candidate, intern_table_candidate) {
            class_linker_offset = Some(candidate);
            output_message(&format!(
                "[art runtime] classLinker 候选 Runtime+{:#x} 验证通过", candidate
            ));
            break;
        }
        output_message(&format!(
            "[art runtime] classLinker 候选 Runtime+{:#x} 验证失败，尝试下一个", candidate
        ));
    }

    // fallback: 如果所有候选都验证失败，取第一个非空指针
    let class_linker_offset = match class_linker_offset {
        Some(off) => off,
        None => {
            output_message("[art runtime] 所有候选交叉验证失败，退回首个非空候选");
            match candidates.iter().find(|&&off| {
                let ptr = safe_read_u64(runtime + off as u64) & PAC_STRIP_MASK;
                ptr != 0
            }) {
                Some(&off) => off,
                None => {
                    output_message("[art runtime] 无有效 classLinker 候选");
                    return None;
                }
            }
        }
    };

    // internTable_ = classLinker_ - 8 (对标 Frida android.js:663)
    let intern_table_offset = class_linker_offset - PTR_SIZE;

    // threadList_ = internTable_ - 8 (对标 Frida android.js:664)
    let thread_list_offset = intern_table_offset - PTR_SIZE;

    // heap_ 偏移 (对标 Frida android.js:666-676)
    let heap_offset = if is_34_equiv {
        // API 34+ / APEX equivalent: threadList - 9*8
        thread_list_offset - 9 * PTR_SIZE
    } else if api_level >= 24 {
        thread_list_offset - 8 * PTR_SIZE
    } else if api_level >= 23 {
        thread_list_offset - 7 * PTR_SIZE
    } else {
        thread_list_offset - 4 * PTR_SIZE
    };

    // jniIdManager_ (API 30+): java_vm_ - 8 (对标 Frida)
    let jni_id_manager_offset = if api_level >= 30 {
        Some(java_vm_off - PTR_SIZE)
    } else {
        None
    };

    // 验证: classLinker 和 internTable 指针非空
    let cl_ptr = safe_read_u64(runtime + class_linker_offset as u64) & PAC_STRIP_MASK;
    let it_ptr = safe_read_u64(runtime + intern_table_offset as u64) & PAC_STRIP_MASK;

    if cl_ptr == 0 {
        output_message("[art runtime] classLinker 指针为空，探测失败");
        return None;
    }

    output_message(&format!(
        "[art runtime] 探测成功: heap={:#x}, threadList={:#x}, internTable={:#x}, classLinker={:#x}{}",
        heap_offset, thread_list_offset, intern_table_offset, class_linker_offset,
        if let Some(jni_off) = jni_id_manager_offset {
            format!(", jniIdManager={:#x}", jni_off)
        } else {
            String::new()
        }
    ));
    output_message(&format!(
        "[art runtime] 验证: classLinker*={:#x}, internTable*={:#x}, Runtime={:#x}",
        cl_ptr, it_ptr, runtime
    ));

    Some(ArtRuntimeSpec {
        heap_offset,
        thread_list_offset,
        intern_table_offset,
        class_linker_offset,
        jni_id_manager_offset,
        runtime_addr: runtime,
    })
}

// ============================================================================
// jniIdsIndirection 偏移探测 — 对标 Frida tryDetectJniIdsIndirectionOffset
// ============================================================================

/// 缓存的 jniIdsIndirection 偏移探测结果
static JNI_IDS_INDIRECTION_OFFSET: OnceLock<Option<usize>> = OnceLock::new();

/// 获取缓存的 jniIdsIndirection 偏移（首次调用时探测）
pub(super) fn get_jni_ids_indirection_offset() -> Option<usize> {
    *JNI_IDS_INDIRECTION_OFFSET.get_or_init(|| probe_jni_ids_indirection_offset())
}

/// 反汇编 art::Runtime::SetJniIdType 提取 Runtime.jni_ids_indirection_ 的偏移。
///
/// 对标 Frida tryDetectJniIdsIndirectionOffset:
/// 扫描前 20 条指令，匹配以下模式之一:
/// - LDR + CMP: LDR 读取 jni_ids_indirection_ 后跟 CMP 比较 → 取 LDR 的位移
/// - STR + BL: STR 写入 jni_ids_indirection_ 后跟 BL 函数调用 → 取 STR 的位移
pub(super) fn probe_jni_ids_indirection_offset() -> Option<usize> {
    // dlsym 查找 art::Runtime::SetJniIdType
    // 注意: 该符号在 Android 12+ 为 PROTECTED visibility，RTLD_DEFAULT 无法找到
    // 必须使用 unrestricted dlsym (对标 Frida 的 linker API)
    let sym = unsafe {
        crate::jsapi::module::libart_dlsym("_ZN3art7Runtime12SetJniIdTypeENS_9JniIdTypeE")
    };
    if sym.is_null() {
        output_message("[jniIds] SetJniIdType 符号未找到");
        return None;
    }

    output_message(&format!("[jniIds] SetJniIdType={:#x}", sym as u64));

    // 扫描前 20 条指令，查找 (LDR + CMP) 或 (STR + BL) 指令对
    let func_addr = sym as u64;
    let mut prev_insn: u32 = 0;
    for i in 0..20u64 {
        let insn = unsafe { *((func_addr + i * 4) as *const u32) };

        if i > 0 {
            // 当前是 CMP 且前一条是 LDR → 取 LDR 的 displacement
            // CMP immediate: SF 11 10001 → mask 0x7F80_0000, Rd=11111 (XZR/WZR)
            let is_cmp_imm = (insn & 0x7F80_0000) == 0x7100_0000 && ((insn & 0x1F) == 0x1F);
            // CMP shifted register: SF 11 01011 → mask 0x7F20_0000 = 0x6B00_0000, Rd=11111
            let is_cmp_reg = (insn & 0x7F20_0000) == 0x6B00_0000 && ((insn & 0x1F) == 0x1F);
            let is_cmp = is_cmp_imm || is_cmp_reg;

            // LDR (unsigned offset): 匹配 32-bit 和 64-bit
            // jni_ids_indirection_ 是 C++ enum (通常 32-bit)，某些编译器生成 LDR W
            // 64-bit: 0xFFC0_0000 == 0xF940_0000, scale=8
            // 32-bit: 0xFFC0_0000 == 0xB940_0000, scale=4
            let prev_is_ldr64 = (prev_insn & 0xFFC0_0000) == 0xF940_0000;
            let prev_is_ldr32 = (prev_insn & 0xFFC0_0000) == 0xB940_0000;

            if is_cmp && (prev_is_ldr64 || prev_is_ldr32) {
                let imm12 = ((prev_insn >> 10) & 0xFFF) as usize;
                let scale = if prev_is_ldr64 { 8 } else { 4 };
                let offset = imm12 * scale;
                output_message(&format!(
                    "[jniIds] LDR+CMP 模式: offset={} ({}bit LDR)",
                    offset, if prev_is_ldr64 { 64 } else { 32 }
                ));
                return Some(offset);
            }

            // 当前是 BL 且前一条是 STR → 取 STR 的 displacement
            let is_bl = (insn & 0xFC00_0000) == 0x9400_0000;
            // STR (unsigned offset): 匹配 32-bit 和 64-bit
            let prev_is_str64 = (prev_insn & 0xFFC0_0000) == 0xF900_0000;
            let prev_is_str32 = (prev_insn & 0xFFC0_0000) == 0xB900_0000;

            if is_bl && (prev_is_str64 || prev_is_str32) {
                let imm12 = ((prev_insn >> 10) & 0xFFF) as usize;
                let scale = if prev_is_str64 { 8 } else { 4 };
                let offset = imm12 * scale;
                output_message(&format!(
                    "[jniIds] STR+BL 模式: offset={} ({}bit STR)",
                    offset, if prev_is_str64 { 64 } else { 32 }
                ));
                return Some(offset);
            }
        }

        prev_insn = insn;
    }

    output_message("[jniIds] 未找到 jniIdsIndirection 偏移");
    None
}
