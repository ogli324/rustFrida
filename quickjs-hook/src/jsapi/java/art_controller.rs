//! ART Controller — 全局 ART 内部函数 hook 模块
//!
//! 三层拦截矩阵:
//!
//! Layer 1: 共享 stub 路由 (全局, hook 一次)
//!   hook_install_art_router(quick_generic_jni_trampoline)
//!   hook_install_art_router(quick_to_interpreter_bridge)
//!   hook_install_art_router(quick_resolution_trampoline)
//!
//! Layer 2: Interpreter DoCall (全局, hook 一次)
//!   hook_attach(DoCall[i], on_do_call_enter)
//!
//! Layer 3: 编译方法独立代码路由 (每个被hook的编译方法)
//!   hook_install_art_router(method.quickCode)
//!   在 java_hook_api.rs 中安装
//!
//! 所有路由通过 replacedMethods 映射查找 replacement ArtMethod。

use crate::ffi::hook as hook_ffi;
use crate::jsapi::console::output_message;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use super::art_method::{ArtBridgeFunctions, ART_BRIDGE_FUNCTIONS, try_invalidate_jit_cache,
                         read_entry_point, get_instrumentation_spec};
use super::art_thread::{get_art_thread_spec, get_managed_stack_spec, ArtThreadSpec, ART_THREAD_SPEC};
use super::callback::{get_replacement_method, is_replacement_method};
use super::jni_core::{JniEnv, get_runtime_addr};
use super::PAC_STRIP_MASK;

// ============================================================================
// wxshadow stealth 全局开关
// ============================================================================

/// 全局开关: 是否对 Java hook 的 inline patch 使用 wxshadow stealth 模式。
/// 启用后 C 层 patch_target 优先尝试 wxshadow，失败自动 fallback 到 mprotect。
static STEALTH_ENABLED: AtomicBool = AtomicBool::new(false);

/// 设置 stealth 开关
pub(super) fn set_stealth_enabled(enabled: bool) {
    STEALTH_ENABLED.store(enabled, Ordering::Relaxed);
    output_message(&format!("[wxshadow] stealth 模式: {}", if enabled { "已启用" } else { "已禁用" }));
}

/// 查询 stealth 开关状态
pub(super) fn is_stealth_enabled() -> bool {
    STEALTH_ENABLED.load(Ordering::Relaxed)
}

/// 返回传给 C hook 函数的 stealth 参数值 (0 或 1)
pub(super) fn stealth_flag() -> i32 {
    is_stealth_enabled() as i32
}

// ============================================================================
// forced_interpret_only — 阻止 JIT 重编译被 hook 方法
// ============================================================================

/// 原始 forced_interpret_only_ 值 (0=未设置, 1=原始为0已设为1, 2=原始已为1)
static FORCED_INTERPRET_SAVED: AtomicU8 = AtomicU8::new(0);

/// 设置 Runtime.Instrumentation.forced_interpret_only_ = 1，阻止 JIT 重编译
///
/// 通过 InstrumentationSpec 获取偏移，从 JavaVM → Runtime → Instrumentation → field。
/// 指针模式: Runtime[offset] 是 Instrumentation*，需先解引用
/// 嵌入模式: Runtime + offset 就是 Instrumentation 结构体的起始地址
unsafe fn set_forced_interpret_only() {
    let spec = match get_instrumentation_spec() {
        Some(s) => s,
        None => {
            output_message("[instrumentation] InstrumentationSpec 不可用，跳过 forced_interpret_only");
            return;
        }
    };

    let runtime = match get_runtime_addr() {
        Some(r) => r,
        None => {
            output_message("[instrumentation] 无法获取 Runtime 地址，跳过 forced_interpret_only");
            return;
        }
    };

    let instrumentation_base = if spec.is_pointer_mode {
        // 指针模式: Runtime[offset] 是 Instrumentation*
        let ptr = *((runtime as usize + spec.runtime_instrumentation_offset) as *const u64);
        let stripped = ptr & PAC_STRIP_MASK;
        if stripped == 0 {
            output_message("[instrumentation] Instrumentation 指针为空");
            return;
        }
        stripped as usize
    } else {
        // 嵌入模式: Runtime + offset 直接是 Instrumentation
        runtime as usize + spec.runtime_instrumentation_offset
    };

    let field_addr = (instrumentation_base + spec.force_interpret_only_offset) as *mut u8;
    let old_val = std::ptr::read_volatile(field_addr);

    if old_val == 0 {
        std::ptr::write_volatile(field_addr, 1);
        FORCED_INTERPRET_SAVED.store(1, Ordering::Relaxed);
        output_message(&format!(
            "[instrumentation] forced_interpret_only_ 已设置 (Instrumentation={:#x}, offset={})",
            instrumentation_base, spec.force_interpret_only_offset
        ));
    } else {
        FORCED_INTERPRET_SAVED.store(2, Ordering::Relaxed);
        output_message("[instrumentation] forced_interpret_only_ 已为1，无需修改");
    }
}

/// 恢复 forced_interpret_only_ 为原始值
unsafe fn restore_forced_interpret_only() {
    let saved = FORCED_INTERPRET_SAVED.load(Ordering::Relaxed);
    if saved != 1 {
        // 0=从未设置, 2=原始就是1 → 不需要恢复
        return;
    }

    let spec = match get_instrumentation_spec() {
        Some(s) => s,
        None => return,
    };

    let runtime = match get_runtime_addr() {
        Some(r) => r,
        None => return,
    };

    let instrumentation_base = if spec.is_pointer_mode {
        let ptr = *((runtime as usize + spec.runtime_instrumentation_offset) as *const u64);
        let stripped = ptr & PAC_STRIP_MASK;
        if stripped == 0 { return; }
        stripped as usize
    } else {
        runtime as usize + spec.runtime_instrumentation_offset
    };

    let field_addr = (instrumentation_base + spec.force_interpret_only_offset) as *mut u8;
    std::ptr::write_volatile(field_addr, 0);
    FORCED_INTERPRET_SAVED.store(0, Ordering::Relaxed);
    output_message("[instrumentation] forced_interpret_only_ 已恢复为 0");
}

// ============================================================================
// ArtController 状态
// ============================================================================

/// 记录已安装的 artController 全局 hook 信息
struct ArtControllerState {
    /// Layer 1: 已 hook 的共享 stub 地址 (jni_trampoline, interpreter_bridge, resolution)
    shared_stub_targets: Vec<u64>,
    /// Layer 2: 已 hook 的 DoCall 函数地址
    do_call_targets: Vec<u64>,
    /// GC 同步 hook 地址 (CopyingPhase, CollectGarbageInternal, RunFlipFunction)
    gc_hook_targets: Vec<u64>,
    /// GetOatQuickMethodHeader hook 地址 (hook_replace, 0 表示未安装)
    oat_header_hook_target: u64,
    /// FixupStaticTrampolines hook 地址 (0 表示未安装)
    fixup_hook_target: u64,
    /// PrettyMethod hook 地址 (0 表示未安装)
    pretty_method_hook_target: u64,
}

unsafe impl Send for ArtControllerState {}
unsafe impl Sync for ArtControllerState {}

/// 全局单例: artController 状态
static ART_CONTROLLER: OnceLock<ArtControllerState> = OnceLock::new();

// ============================================================================
// 初始化
// ============================================================================

/// 惰性初始化 artController: 安装 Layer 1 (共享 stub 路由) + Layer 2 (DoCall hook)。
///
/// 使用 OnceLock 保证只初始化一次。首次调用 Java.hook() 时触发。
///
/// Layer 1: 对 3 个共享 stub 安装 hook_install_art_router，路由 hook 方法到 replacement
/// Layer 2: 对 DoCall 安装 hook_attach，拦截解释器路径
pub(super) fn ensure_art_controller_initialized(bridge: &ArtBridgeFunctions, ep_offset: usize, env: *mut std::ffi::c_void) {
    ART_CONTROLLER.get_or_init(|| {
        output_message("[artController] 开始安装三层拦截矩阵...");

        // 提前探测 ArtThreadSpec (递归防护 stack check 需要)
        let _ = get_art_thread_spec(env as JniEnv);
        let _ = get_managed_stack_spec();

        // B3: 自动清空 JIT 缓存 — 使已内联被 hook 方法的 JIT 代码失效
        unsafe { try_invalidate_jit_cache(); }

        // B4: 设置 forced_interpret_only — 阻止 JIT 重编译
        unsafe { set_forced_interpret_only(); }

        let mut shared_stub_targets = Vec::new();
        let mut do_call_targets = Vec::new();

        // --- Layer 1: 共享 stub 路由 hook ---
        let stubs = [
            ("quick_generic_jni_trampoline", bridge.quick_generic_jni_trampoline),
            ("quick_to_interpreter_bridge", bridge.quick_to_interpreter_bridge),
            ("quick_resolution_trampoline", bridge.quick_resolution_trampoline),
        ];

        for (name, addr) in &stubs {
            if *addr == 0 {
                output_message(&format!("[artController] Layer 1: {} 地址为0，跳过", name));
                continue;
            }
            let mut hooked_target: *mut std::ffi::c_void = std::ptr::null_mut();
            let trampoline = unsafe {
                hook_ffi::hook_install_art_router(
                    *addr as *mut std::ffi::c_void,
                    ep_offset as u32,
                    stealth_flag(),
                    env,
                    &mut hooked_target,
                )
            };
            if !trampoline.is_null() {
                // 使用实际被 hook 的地址 (可能经过 resolve_art_trampoline 解析)
                let actual_target = if !hooked_target.is_null() {
                    hooked_target as u64
                } else {
                    *addr
                };
                shared_stub_targets.push(actual_target);
                output_message(&format!(
                    "[artController] Layer 1: {} hook 安装成功: {:#x} (hooked={:#x}), trampoline={:#x}",
                    name, addr, actual_target, trampoline as u64
                ));
            } else {
                output_message(&format!(
                    "[artController] Layer 1: {} hook 安装失败: {:#x}", name, addr
                ));
            }
        }

        // --- Layer 2: DoCall hook (解释器路径) ---
        for (i, &addr) in bridge.do_call_addrs.iter().enumerate() {
            if addr == 0 {
                continue;
            }
            let ret = unsafe {
                hook_ffi::hook_attach(
                    addr as *mut std::ffi::c_void,
                    Some(on_do_call_enter),
                    None,
                    std::ptr::null_mut(),
                    stealth_flag(),
                )
            };
            if ret == 0 {
                do_call_targets.push(addr);
                output_message(&format!(
                    "[artController] Layer 2: DoCall[{}] hook 安装成功: {:#x}", i, addr
                ));
            } else {
                output_message(&format!(
                    "[artController] Layer 2: DoCall[{}] hook 安装失败: {:#x} (ret={})", i, addr, ret
                ));
            }
        }

        // --- GC 同步 hooks ---
        // GC 可能移动 ArtMethod 的 entry_point / declaring_class_，需要在多个 GC 点同步
        let mut gc_hook_targets = Vec::new();

        // Fix 3: hook CopyingPhase/MarkingPhase on_leave
        if bridge.gc_copying_phase != 0 {
            let ret = unsafe {
                hook_ffi::hook_attach(
                    bridge.gc_copying_phase as *mut std::ffi::c_void,
                    None,
                    Some(on_gc_sync_leave),
                    std::ptr::null_mut(),
                    stealth_flag(),
                )
            };
            if ret == 0 {
                gc_hook_targets.push(bridge.gc_copying_phase);
                output_message(&format!(
                    "[artController] GC CopyingPhase hook 安装成功: {:#x}", bridge.gc_copying_phase
                ));
            } else {
                output_message(&format!(
                    "[artController] GC CopyingPhase hook 安装失败: {:#x} (ret={})",
                    bridge.gc_copying_phase, ret
                ));
            }
        }

        // Fix 3: hook CollectGarbageInternal on_leave (主 GC 入口)
        if bridge.gc_collect_internal != 0 {
            let ret = unsafe {
                hook_ffi::hook_attach(
                    bridge.gc_collect_internal as *mut std::ffi::c_void,
                    None,
                    Some(on_gc_sync_leave),
                    std::ptr::null_mut(),
                    stealth_flag(),
                )
            };
            if ret == 0 {
                gc_hook_targets.push(bridge.gc_collect_internal);
                output_message(&format!(
                    "[artController] GC CollectGarbageInternal hook 安装成功: {:#x}",
                    bridge.gc_collect_internal
                ));
            } else {
                output_message(&format!(
                    "[artController] GC CollectGarbageInternal hook 安装失败: {:#x} (ret={})",
                    bridge.gc_collect_internal, ret
                ));
            }
        }

        // Fix 3: hook RunFlipFunction on_enter (线程翻转期间同步)
        if bridge.run_flip_function != 0 {
            let ret = unsafe {
                hook_ffi::hook_attach(
                    bridge.run_flip_function as *mut std::ffi::c_void,
                    Some(on_gc_sync_enter),
                    None,
                    std::ptr::null_mut(),
                    stealth_flag(),
                )
            };
            if ret == 0 {
                gc_hook_targets.push(bridge.run_flip_function);
                output_message(&format!(
                    "[artController] GC RunFlipFunction hook 安装成功: {:#x}",
                    bridge.run_flip_function
                ));
            } else {
                output_message(&format!(
                    "[artController] GC RunFlipFunction hook 安装失败: {:#x} (ret={})",
                    bridge.run_flip_function, ret
                ));
            }
        }

        // --- Fix 4: hook GetOatQuickMethodHeader (replace mode) ---
        // 对 replacement method 返回 NULL，防止 ART 查找堆分配方法的 OAT 代码头
        let mut oat_header_hook_target: u64 = 0;
        if bridge.get_oat_quick_method_header != 0 {
            let trampoline = unsafe {
                hook_ffi::hook_replace(
                    bridge.get_oat_quick_method_header as *mut std::ffi::c_void,
                    Some(on_get_oat_quick_method_header),
                    std::ptr::null_mut(),
                    stealth_flag(),
                )
            };
            if !trampoline.is_null() {
                oat_header_hook_target = bridge.get_oat_quick_method_header;
                output_message(&format!(
                    "[artController] GetOatQuickMethodHeader hook 安装成功: {:#x}, trampoline={:#x}",
                    bridge.get_oat_quick_method_header, trampoline as u64
                ));
            } else {
                output_message(&format!(
                    "[artController] GetOatQuickMethodHeader hook 安装失败: {:#x}",
                    bridge.get_oat_quick_method_header
                ));
            }
        }

        // --- Fix 5: hook FixupStaticTrampolines on_leave ---
        // 类初始化完成后同步 replacement 方法，防止 quickCode 被更新绕过 hook
        let mut fixup_hook_target: u64 = 0;
        if bridge.fixup_static_trampolines != 0 {
            let ret = unsafe {
                hook_ffi::hook_attach(
                    bridge.fixup_static_trampolines as *mut std::ffi::c_void,
                    None,
                    Some(on_gc_sync_leave),
                    std::ptr::null_mut(),
                    stealth_flag(),
                )
            };
            if ret == 0 {
                fixup_hook_target = bridge.fixup_static_trampolines;
                output_message(&format!(
                    "[artController] FixupStaticTrampolines hook 安装成功: {:#x}",
                    bridge.fixup_static_trampolines
                ));
            } else {
                output_message(&format!(
                    "[artController] FixupStaticTrampolines hook 安装失败: {:#x} (ret={})",
                    bridge.fixup_static_trampolines, ret
                ));
            }
        }

        // --- Fix: hook PrettyMethod (NULL 指针崩溃防护) ---
        let mut pretty_method_hook_target: u64 = 0;
        if bridge.pretty_method != 0 {
            let ret = unsafe {
                hook_ffi::hook_attach(
                    bridge.pretty_method as *mut std::ffi::c_void,
                    Some(on_pretty_method_enter),
                    None,
                    std::ptr::null_mut(),
                    stealth_flag(),
                )
            };
            if ret == 0 {
                pretty_method_hook_target = bridge.pretty_method;
                output_message(&format!(
                    "[artController] PrettyMethod hook 安装成功: {:#x}",
                    bridge.pretty_method
                ));
            } else {
                output_message(&format!(
                    "[artController] PrettyMethod hook 安装失败: {:#x} (ret={})",
                    bridge.pretty_method, ret
                ));
            }
        }

        output_message(&format!(
            "[artController] 初始化完成: Layer1={}, Layer2={}, GC={}, OatHeader={}, Fixup={}, PrettyMethod={}",
            shared_stub_targets.len(),
            do_call_targets.len(),
            gc_hook_targets.len(),
            if oat_header_hook_target != 0 { "active" } else { "none" },
            if fixup_hook_target != 0 { "active" } else { "none" },
            if pretty_method_hook_target != 0 { "active" } else { "none" },
        ));

        ArtControllerState {
            shared_stub_targets,
            do_call_targets,
            gc_hook_targets,
            oat_header_hook_target,
            fixup_hook_target,
            pretty_method_hook_target,
        }
    });
}

// ============================================================================
// 回调函数
// ============================================================================

/// 获取已缓存的 ArtThreadSpec（不需要 JNIEnv，仅从 OnceLock 读取）
fn get_art_thread_spec_cached() -> Option<&'static ArtThreadSpec> {
    match ART_THREAD_SPEC.get() {
        Some(Some(spec)) => Some(spec),
        _ => None,
    }
}

/// DoCall on_enter: 检查 x0 (ArtMethod*) 是否在 replacedMethods 中，有则替换。
/// 包含递归防护: 如果当前栈帧来自 callOriginal (managedStack 中已有 replacement)，
/// 则跳过替换，让 original method 正常执行，防止无限递归。
unsafe extern "C" fn on_do_call_enter(
    ctx_ptr: *mut hook_ffi::HookContext,
    _user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = &mut *ctx_ptr;
    let method = ctx.x[0];
    if let Some(replacement) = get_replacement_method(method) {
        // 递归防护: 检查 managedStack 是否表明这是 callOriginal 发起的调用
        if !should_replace_for_stack(replacement) {
            return; // 递归情况，保持 original 不替换
        }
        // 同步 declaring_class_ (offset 0, 4B GcRoot): original → replacement
        // GC 可能已更新 original 的 declaring_class_ 但堆分配的 replacement 未被 GC 追踪，
        // 在路由时内联同步消除 GC 与 sync 回调之间的竞态窗口
        let declaring_class = std::ptr::read_volatile(method as *const u32);
        std::ptr::write_volatile(replacement as *mut u32, declaring_class);
        ctx.x[0] = replacement;
    }
}

/// 递归防护: 检查当前线程的 ManagedStack 判断是否应该进行替换。
///
/// 对标 Frida find_replacement_method_from_quick_code():
/// 1. 获取 Thread* via Thread::Current()
/// 2. 读取 managed_stack.top_quick_frame
/// 3. 如果 top_quick_frame != NULL → 正常调用，返回 true
/// 4. 读取 managed_stack.link
/// 5. 读取 link.top_quick_frame，解引用得到 ArtMethod*
/// 6. 如果该 ArtMethod* == replacement → 递归，返回 false
/// 7. 否则返回 true
unsafe fn should_replace_for_stack(replacement: u64) -> bool {
    // 获取 Thread::Current 函数指针
    let bridge = match ART_BRIDGE_FUNCTIONS.get() {
        Some(b) => b,
        None => return true,
    };
    if bridge.thread_current == 0 {
        return true; // 无法获取 Thread*，保守返回 true
    }

    // 调用 Thread::Current() 获取当前线程
    type ThreadCurrentFn = unsafe extern "C" fn() -> u64;
    let thread_current: ThreadCurrentFn = std::mem::transmute(bridge.thread_current);
    let thread = thread_current();
    let thread = thread & PAC_STRIP_MASK;
    if thread == 0 {
        return true;
    }

    // 获取 Thread 和 ManagedStack 布局偏移
    // 注意: get_art_thread_spec 需要 JNIEnv，但此处已经在 hook 回调中，
    // 且 spec 应该已经在初始化时被探测过。使用 OnceLock 缓存值。
    let thread_spec = match get_art_thread_spec_cached() {
        Some(spec) => spec,
        None => return true,
    };
    let ms_spec = get_managed_stack_spec();

    // 读取 managed_stack (嵌入在 Thread 结构体中)
    let managed_stack = thread as usize + thread_spec.managed_stack_offset;

    // 读取 top_quick_frame
    let top_qf = std::ptr::read_volatile(
        (managed_stack + ms_spec.top_quick_frame_offset) as *const u64,
    );

    if top_qf != 0 {
        // top_quick_frame != NULL → 正常调用 (有 compiled frame)，执行替换
        return true;
    }

    // top_quick_frame == NULL → 可能是从解释器进入的
    // 读取 link_ (上一个 ManagedStack)
    let link = std::ptr::read_volatile(
        (managed_stack + ms_spec.link_offset) as *const u64,
    );
    let link = link & PAC_STRIP_MASK;
    if link == 0 {
        return true;
    }

    // 读取 link.top_quick_frame (可能有 TaggedQuickFrame 的 tag bit)
    let link_tqf = std::ptr::read_volatile(
        (link as usize + ms_spec.top_quick_frame_offset) as *const u64,
    );
    // Strip tag bit (bit 0): ART uses it as a tag for managed/JNI frames
    let frame_ptr = (link_tqf & !1u64) & PAC_STRIP_MASK;
    if frame_ptr == 0 {
        return true;
    }

    // Dereference: top_quick_frame 指向栈上的 ArtMethod*
    let art_method_on_stack = std::ptr::read_volatile(frame_ptr as *const u64);
    let art_method_on_stack = art_method_on_stack & PAC_STRIP_MASK;

    if art_method_on_stack == replacement {
        // 栈上的方法就是 replacement → 这是 callOriginal 触发的递归调用
        false
    } else {
        true
    }
}

/// 上次见到的非空 ArtMethod* (PrettyMethod 防护用)
static LAST_SEEN_ART_METHOD: AtomicU64 = AtomicU64::new(0);

/// PrettyMethod on_enter 回调: 当 method (x0/this) 为 NULL 时替换为上次见到的非空 method。
/// 对标 Frida fixupArtQuickDeliverExceptionBug: QuickDeliverException 中
/// native 线程无 Java frame 时 method==NULL → PrettyMethod(NULL) → SIGSEGV。
unsafe extern "C" fn on_pretty_method_enter(
    ctx_ptr: *mut hook_ffi::HookContext,
    _user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = &mut *ctx_ptr;
    let method = ctx.x[0]; // ARM64: this (ArtMethod*) 在 x0
    if method == 0 {
        // NULL method → 替换为上次见到的非空 method 防止崩溃
        let last = LAST_SEEN_ART_METHOD.load(Ordering::Relaxed);
        if last != 0 {
            ctx.x[0] = last;
        }
    } else {
        LAST_SEEN_ART_METHOD.store(method, Ordering::Relaxed);
    }
}

/// GC / FixupStaticTrampolines on_leave 回调: 调用同步函数
unsafe extern "C" fn on_gc_sync_leave(
    _ctx_ptr: *mut hook_ffi::HookContext,
    _user_data: *mut std::ffi::c_void,
) {
    synchronize_replacement_methods();
}

/// RunFlipFunction on_enter 回调: 线程翻转期间同步
unsafe extern "C" fn on_gc_sync_enter(
    _ctx_ptr: *mut hook_ffi::HookContext,
    _user_data: *mut std::ffi::c_void,
) {
    synchronize_replacement_methods();
}

/// Fix 4: GetOatQuickMethodHeader replace-mode 回调
///
/// 对 replacement ArtMethod 返回 NULL，防止 ART 查找堆分配方法的 OAT 代码头。
/// 对其他方法调用原始实现。
unsafe extern "C" fn on_get_oat_quick_method_header(
    ctx_ptr: *mut hook_ffi::HookContext,
    _user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() {
        return;
    }
    let ctx = &mut *ctx_ptr;
    let method = ctx.x[0]; // ArtMethod* this

    if is_replacement_method(method) {
        // replacement method → return NULL
        ctx.x[0] = 0;
    } else {
        // 非 replacement → 调用原始实现
        let trampoline = ctx.trampoline;
        if !trampoline.is_null() {
            let result = hook_ffi::hook_invoke_trampoline(ctx_ptr, trampoline);
            (*ctx_ptr).x[0] = result;
        }
    }
}

// ============================================================================
// Fix 6: synchronize_replacement_methods — 统一同步函数
// ============================================================================

/// 同步所有被 hook 方法的关键字段。
///
/// 在多个 ART 内部事件（GC、类初始化等）后调用，确保 hook 仍然生效。
///
/// 同步内容:
/// 1. declaring_class_ 同步: original → replacement (Fix 1)
/// 2. accessFlags 修复: kAccCompileDontBother + clear kAccFastInterpreterToInterpreterInvoke
/// 3. entry_point 验证与恢复 (Fix 2 + existing)
unsafe fn synchronize_replacement_methods() {
    use super::art_method::ART_BRIDGE_FUNCTIONS;
    use super::callback::{JAVA_HOOK_REGISTRY, HookType};
    use super::jni_core::{ART_METHOD_SPEC, k_acc_compile_dont_bother,
                          K_ACC_FAST_INTERP_TO_INTERP};

    let guard = match JAVA_HOOK_REGISTRY.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    let registry = match guard.as_ref() {
        Some(r) => r,
        None => return,
    };

    let spec = match ART_METHOD_SPEC.get() {
        Some(s) => s,
        None => return,
    };
    let ep_offset = spec.entry_point_offset;

    // 获取 nterp 和 interpreter_bridge 地址 (共享 stub 方法的 GC 同步用)
    let (nterp, interp_bridge) = match ART_BRIDGE_FUNCTIONS.get() {
        Some(b) => (b.nterp_entry_point, b.quick_to_interpreter_bridge),
        None => (0, 0),
    };

    for (_, data) in registry.iter() {
        let art_method = data.art_method as usize;

        // --- Fix 1: declaring_class_ 同步 ---
        // 移动 GC 会更新原始 ArtMethod 的 declaring_class_ (offset 0, 4 bytes GcRoot)，
        // 但堆分配的 replacement 和 clone 不会被 GC 追踪。同步以防悬空引用。
        let HookType::Replaced { replacement_addr, .. } = &data.hook_type;
        {
            let declaring_class = std::ptr::read_volatile(art_method as *const u32);
            std::ptr::write_volatile(*replacement_addr as *mut u32, declaring_class);
            // 同步到 clone (callOriginal 使用的备份 ArtMethod)
            if data.clone_addr != 0 {
                std::ptr::write_volatile(data.clone_addr as *mut u32, declaring_class);
            }
        }

        // --- flags 修复: 确保 kAccCompileDontBother 在 + kAccFastInterpreterToInterpreterInvoke 不在 ---
        let cdontbother = k_acc_compile_dont_bother();
        let flags = std::ptr::read_volatile(
            (art_method + spec.access_flags_offset) as *const u32,
        );
        let need_fix = (cdontbother != 0 && (flags & cdontbother) == 0)
            || (flags & K_ACC_FAST_INTERP_TO_INTERP) != 0;
        if need_fix {
            let fixed = (flags | cdontbother) & !K_ACC_FAST_INTERP_TO_INTERP;
            std::ptr::write_volatile(
                (art_method + spec.access_flags_offset) as *mut u32,
                fixed,
            );
        }

        // --- Fix 2 + existing: entry_point 验证与恢复 ---
        match &data.hook_type {
            HookType::Replaced { per_method_hook_target: None, .. } => {
                // 共享 stub 方法: 如果 GC 重置 entry_point 为 nterp，再降级为 interpreter_bridge
                if nterp != 0 && interp_bridge != 0 {
                    let current_ep = read_entry_point(data.art_method, ep_offset);
                    if current_ep == nterp {
                        std::ptr::write_volatile(
                            (art_method + ep_offset) as *mut u64,
                            interp_bridge,
                        );
                        hook_ffi::hook_flush_cache(
                            (art_method + ep_offset) as *mut std::ffi::c_void,
                            8,
                        );
                    }
                }
            }
            HookType::Replaced { per_method_hook_target: Some(_), .. } => {
                // 编译方法: entry_point 应为 original_entry_point (已被 inline hook 修改)
                let current_ep = read_entry_point(data.art_method, ep_offset);
                if current_ep != data.original_entry_point {
                    // GC/类初始化 重置了 entry_point (可能变为 nterp)，恢复到被 patch 的原始地址
                    std::ptr::write_volatile(
                        (art_method + ep_offset) as *mut u64,
                        data.original_entry_point,
                    );
                    hook_ffi::hook_flush_cache(
                        (art_method + ep_offset) as *mut std::ffi::c_void,
                        8,
                    );
                }
            }
        }
    }
}

// ============================================================================
// 清理
// ============================================================================

/// 清理所有 artController 全局 hook
///
/// 移除 Layer 1 (共享 stub 路由 hook) 和 Layer 2 (DoCall hook)。
/// 调用路径: cleanup_java_hooks() → cleanup_art_controller()
/// 幂等保护: cleanup_art_controller 只执行一次
static ART_CONTROLLER_CLEANED: AtomicBool = AtomicBool::new(false);

pub(super) fn cleanup_art_controller() {
    // 幂等: JSEngine::Drop 和 cleanup_java_hooks 都可能调用此函数
    if ART_CONTROLLER_CLEANED.swap(true, Ordering::SeqCst) {
        return;
    }

    // 恢复 instrumentation 状态 (在移除 hooks 之前)
    unsafe { restore_forced_interpret_only(); }

    let state = match ART_CONTROLLER.get() {
        Some(s) => s,
        None => return, // 从未初始化，无需清理
    };

    output_message("[artController] 开始清理全局 ART hook...");

    // 收集所有需要移除的地址，统一移除
    let mut all_targets: Vec<(&str, u64)> = Vec::new();
    for &addr in &state.shared_stub_targets {
        all_targets.push(("Layer1", addr));
    }
    for &addr in &state.do_call_targets {
        all_targets.push(("Layer2", addr));
    }
    for &addr in &state.gc_hook_targets {
        all_targets.push(("GC", addr));
    }
    if state.oat_header_hook_target != 0 {
        all_targets.push(("OatHeader", state.oat_header_hook_target));
    }
    if state.fixup_hook_target != 0 {
        all_targets.push(("Fixup", state.fixup_hook_target));
    }
    if state.pretty_method_hook_target != 0 {
        all_targets.push(("PrettyMethod", state.pretty_method_hook_target));
    }

    for (_label, addr) in &all_targets {
        unsafe {
            hook_ffi::hook_remove(*addr as *mut std::ffi::c_void);
        }
    }

    output_message("[artController] 全局 ART hook 清理完成");
}
