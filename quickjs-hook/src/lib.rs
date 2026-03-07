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
pub mod runtime;
pub mod value;

pub use completion::complete_script;
pub use context::JSContext;
pub use jsapi::console::set_console_callback;
pub use jsapi::hook_api::cleanup_hooks;
pub use jsapi::java::cleanup_java_hooks;
pub use runtime::JSRuntime;
pub use value::JSValue;

use std::sync::Mutex;

/// Global JS engine instance (protected by Mutex).
/// pub(crate) so hook_callback_wrapper can serialize concurrent JS_Call invocations.
pub(crate) static JS_ENGINE: Mutex<Option<JSEngine>> = Mutex::new(None);

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

/// Enter bulk cleanup mode: skip per-hook wxshadow release + re-patch
pub fn begin_bulk_cleanup() {
    unsafe {
        ffi::hook::hook_engine_begin_bulk_cleanup();
    }
}

/// Begin batch unhook: defer wxshadow release + re-patch to end_batch()
pub fn begin_batch() {
    unsafe {
        ffi::hook::hook_begin_batch();
    }
}

/// End batch unhook: release dirty pages once, re-patch survivors
pub fn end_batch() {
    unsafe {
        ffi::hook::hook_end_batch();
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
    let value = engine.eval(script)?;
    engine.run_pending_jobs();
    let result = if value.is_undefined() {
        "undefined".to_string()
    } else {
        value
            .to_string(engine.context().as_ptr())
            .unwrap_or_default()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        // This test may fail if QuickJS is not built
        // It's mainly for development verification
    }
}
