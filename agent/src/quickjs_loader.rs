//! QuickJS loader module for the agent
//!
//! This module provides JavaScript loading and execution capabilities
//! using the quickjs-hook crate.

#![cfg(feature = "quickjs")]

use quickjs_hook::{
    begin_bulk_cleanup, cleanup_engine, cleanup_hook_engine, cleanup_hooks, cleanup_java_hooks,
    complete_script, get_or_init_engine, init_hook_engine, load_script, set_console_callback,
};
use libc::{mmap, munmap, PROT_READ, PROT_WRITE, PROT_EXEC, MAP_PRIVATE, MAP_ANONYMOUS, sysconf, _SC_PAGESIZE};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use crate::communication::{write_stream, log_msg};

static ENGINE_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Executable memory for hooks
static EXEC_MEM: OnceLock<ExecMemory> = OnceLock::new();

/// Executable memory region wrapper
struct ExecMemory {
    ptr: *mut u8,
    size: usize,
}

impl ExecMemory {
    /// Allocate new executable memory
    fn new(size: usize) -> Option<Self> {
        let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
        let alloc_size = ((size + page_size - 1) / page_size) * page_size;

        unsafe {
            let ptr = mmap(
                ptr::null_mut(),
                alloc_size,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );

            if ptr == libc::MAP_FAILED {
                return None;
            }

            Some(ExecMemory {
                ptr: ptr as *mut u8,
                size: alloc_size,
            })
        }
    }

    fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    fn size(&self) -> usize {
        self.size
    }
}

impl Drop for ExecMemory {
    fn drop(&mut self) {
        unsafe {
            munmap(self.ptr as *mut _, self.size);
        }
    }
}

// Safety: ExecMemory is only accessed from the JS thread
unsafe impl Send for ExecMemory {}
unsafe impl Sync for ExecMemory {}

/// Initialize the QuickJS engine and hook system
pub fn init() -> Result<(), String> {
    if ENGINE_INITIALIZED.load(Ordering::SeqCst) {
        return Err("JS 引擎已初始化".to_string());
    }

    // Allocate executable memory for hooks (64KB)
    let exec_mem = EXEC_MEM
        .get_or_init(|| ExecMemory::new(64 * 1024).expect("Failed to allocate executable memory"));

    // Initialize hook engine
    init_hook_engine(exec_mem.as_ptr(), exec_mem.size())?;

    // 先设置 console callback，确保引擎初始化期间的日志（如 [jniIds]）能通过 socket 输出
    set_console_callback(|msg| {
        write_stream(format!("[JS] {}\n", msg).as_bytes());
    });

    // 初始化 JS 引擎（complete_script 依赖它）
    get_or_init_engine()?;

    ENGINE_INITIALIZED.store(true, Ordering::SeqCst);

    Ok(())
}

/// Load and execute a JavaScript script
pub fn execute_script(script: &str) -> Result<String, String> {
    if !ENGINE_INITIALIZED.load(Ordering::SeqCst) {
        return Err("JS 引擎未初始化，请先执行 jsinit".to_string());
    }

    load_script(script)
}

/// Get tab-completion candidates for the given prefix from the live JS engine.
pub fn complete(prefix: &str) -> String {
    if !ENGINE_INITIALIZED.load(Ordering::SeqCst) {
        return String::new();
    }
    let candidates = complete_script(prefix);
    candidates.join("\t")
}

/// 检查 JS 引擎是否已初始化
pub fn is_initialized() -> bool {
    ENGINE_INITIALIZED.load(Ordering::SeqCst)
}

/// Cleanup QuickJS resources
pub fn cleanup() {
    ENGINE_INITIALIZED.store(false, Ordering::SeqCst);
    // Bulk cleanup mode: skip per-hook wxshadow release + re-patch,
    // wxshadow_release_all() in hook_engine_cleanup() handles them in one shot
    begin_bulk_cleanup();
    // Unhook Java hooks first (restore ArtMethod entry points)
    cleanup_java_hooks();
    // Unhook all inline hooks while the JS context (ctx) is still valid
    cleanup_hooks();
    // Destroy JSEngine (JS_FreeContext + JS_FreeRuntime)
    cleanup_engine();
    // Reset hook engine state (wxshadow_release_all + free pool)
    cleanup_hook_engine();
}
