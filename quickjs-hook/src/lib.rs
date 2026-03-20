//! quickjs-hook - QuickJS JavaScript engine with inline hook support for ARM64 Android
//!
//! This crate provides:
//! - QuickJS JavaScript engine bindings
//! - ARM64 inline hook engine
//! - Frida-style JavaScript API for hooking
//!
//! # Example
//!
//! ```rust,ignore
//! use quickjs_hook::{JSEngine, init_hook_engine};
//!
//! // Initialize hook engine with executable memory
//! init_hook_engine(exec_mem, size).unwrap();
//!
//! // Create JS engine and run script
//! let engine = JSEngine::new().unwrap();
//! engine.eval(r#"
//!     console.log("Hello from QuickJS!");
//!     hook(ptr("0x12345678"), function(ctx) {
//!         console.log("Hooked! x0=" + ctx.x0);
//!     });
//! "#).unwrap();
//! ```

#![allow(clippy::missing_safety_doc)]

mod completion;
pub mod context;
pub mod ffi;
pub mod jsapi;
pub mod recomp;
pub mod runtime;
pub mod value;

pub use completion::complete_script;
pub use context::JSContext;
pub use jsapi::console::set_console_callback;
pub use jsapi::hook_api::cleanup_hooks;
#[cfg(feature = "qbdi")]
pub use jsapi::hook_api::preload_qbdi_helper;
#[cfg(feature = "qbdi")]
pub use jsapi::hook_api::shutdown_qbdi_helper;
pub use jsapi::java::cleanup_java_hooks;
pub use jsapi::deferred_java_init;
pub use runtime::JSRuntime;
pub use value::JSValue;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

static QBDI_OUTPUT_DIR: OnceLock<String> = OnceLock::new();
static QBDI_HELPER_BLOB: Mutex<Option<Vec<u8>>> = Mutex::new(None);

pub fn set_qbdi_output_dir(output_dir: impl Into<String>) {
    let _ = QBDI_OUTPUT_DIR.set(output_dir.into());
}

pub fn set_qbdi_helper_blob(blob: Vec<u8>) {
    *QBDI_HELPER_BLOB.lock().unwrap_or_else(|e| e.into_inner()) = Some(blob);
}

pub(crate) fn qbdi_output_dir() -> Option<&'static str> {
    QBDI_OUTPUT_DIR.get().map(|s| s.as_str())
}

pub(crate) fn qbdi_helper_blob() -> Option<Vec<u8>> {
    QBDI_HELPER_BLOB.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Global JS engine instance (protected by Mutex).
/// pub(crate) so hook_callback_wrapper can serialize concurrent JS_Call invocations.
pub(crate) static JS_ENGINE: Mutex<Option<JSEngine>> = Mutex::new(None);
/// Best-effort owner tracking for the thread currently executing inside the global JS engine.
/// Used by hook callbacks to distinguish same-thread reentrancy from ordinary contention.
pub(crate) static JS_ENGINE_OWNER_THREAD: AtomicU64 = AtomicU64::new(0);

#[inline]
pub(crate) fn current_thread_id_u64() -> u64 {
    unsafe { libc::pthread_self() as usize as u64 }
}

#[inline]
pub(crate) fn mark_js_engine_owner_current_thread() {
    JS_ENGINE_OWNER_THREAD.store(current_thread_id_u64(), Ordering::Release);
}

#[inline]
pub(crate) fn clear_js_engine_owner_current_thread() {
    let current = current_thread_id_u64();
    let _ = JS_ENGINE_OWNER_THREAD.compare_exchange(current, 0, Ordering::AcqRel, Ordering::Relaxed);
}

struct JsEngineOwnerGuard;

impl JsEngineOwnerGuard {
    fn acquire() -> Self {
        mark_js_engine_owner_current_thread();
        JsEngineOwnerGuard
    }
}

impl Drop for JsEngineOwnerGuard {
    fn drop(&mut self) {
        clear_js_engine_owner_current_thread();
    }
}

/// Log callback registered with the C hook engine.
/// Routes hook_engine diagnostic messages through the JS console callback
/// so they appear in the REPL output alongside normal [JS] messages.
unsafe extern "C" fn hook_engine_log_impl(msg: *const std::os::raw::c_char) {
    if msg.is_null() {
        return;
    }
    let s = std::ffi::CStr::from_ptr(msg).to_string_lossy();
    crate::jsapi::console::output_message(&format!("[hook_engine] {}", s));
}

/// Initialize the hook engine with executable memory
///
/// # Arguments
/// * `exec_mem` - Pointer to executable memory region (must be RWX)
/// * `size` - Size of the memory region in bytes
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` on failure
pub fn init_hook_engine(exec_mem: *mut u8, size: usize) -> Result<(), String> {
    let result = unsafe { ffi::hook::hook_engine_init(exec_mem as *mut _, size) };

    if result == 0 {
        // Register log callback so wxshadow/prctl diagnostics appear in REPL
        unsafe { ffi::hook::hook_engine_set_log_fn(Some(hook_engine_log_impl)) };
        Ok(())
    } else {
        Err("Failed to initialize hook engine".to_string())
    }
}

/// Cleanup the hook engine
pub fn cleanup_hook_engine() {
    unsafe {
        ffi::hook::hook_engine_cleanup();
    }
}

/// High-level JS engine wrapper
/// Note: Field order matters for drop order - context must be dropped before runtime
pub struct JSEngine {
    context: JSContext,
    runtime: JSRuntime,
}

impl JSEngine {
    /// Create a new JS engine with all APIs registered
    pub fn new() -> Option<Self> {
        let runtime = JSRuntime::new()?;
        let context = runtime.new_context()?;

        // Register all JavaScript APIs
        jsapi::register_all_apis(&context);

        Some(JSEngine { runtime, context })
    }

    /// Evaluate a JavaScript script
    pub fn eval(&self, script: &str) -> Result<JSValue, String> {
        self.context.eval(script, "<eval>")
    }

    /// Evaluate a script with a specific filename
    pub fn eval_file(&self, script: &str, filename: &str) -> Result<JSValue, String> {
        self.context.eval(script, filename)
    }

    /// Get the JS context
    pub fn context(&self) -> &JSContext {
        &self.context
    }

    /// Get the JS runtime
    pub fn runtime(&self) -> &JSRuntime {
        &self.runtime
    }

    /// Execute pending jobs (for promises)
    pub fn run_pending_jobs(&self) {
        while self.context.execute_pending_job() {}
    }
}

impl Drop for JSEngine {
    fn drop(&mut self) {
        // Cleanup Java hooks first (they depend on redirect thunks in the hook engine)
        cleanup_java_hooks();
        // Cleanup inline hooks before dropping context
        cleanup_hooks();
    }
}

// Safety: JSEngine is protected by Mutex, ensuring single-threaded access
unsafe impl Send for JSEngine {}
unsafe impl Sync for JSEngine {}

/// Get or initialize the global JS engine
pub fn get_or_init_engine() -> Result<(), String> {
    let mut engine = JS_ENGINE
        .lock()
        .map_err(|e| format!("Failed to lock JS engine: {}", e))?;
    if engine.is_none() {
        *engine = Some(JSEngine::new().ok_or_else(|| "Failed to create JS engine".to_string())?);
    }
    Ok(())
}

/// Load and execute a JavaScript script using the global engine.
/// Returns the string representation of the result, or an empty string for `undefined`.
pub fn load_script(script: &str) -> Result<String, String> {
    let mut engine = JS_ENGINE
        .lock()
        .map_err(|e| format!("Failed to lock JS engine: {}", e))?;
    if engine.is_none() {
        *engine = Some(JSEngine::new().ok_or_else(|| "Failed to create JS engine".to_string())?);
    }
    let engine = engine.as_ref().ok_or("JS engine not initialized")?;
    let _owner_guard = JsEngineOwnerGuard::acquire();
    let value = engine.eval(script)?;
    engine.run_pending_jobs();
    let result = if value.is_undefined() {
        "undefined".to_string()
    } else {
        value.to_string(engine.context().as_ptr()).unwrap_or_default()
    };
    value.free(engine.context().as_ptr());
    Ok(result)
}

/// Cleanup the global JS engine
pub fn cleanup_engine() {
    if let Ok(mut engine) = JS_ENGINE.lock() {
        *engine = None;
    }
}
