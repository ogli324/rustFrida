//! Java hook callback and registry + replacedMethods mapping
//!
//! Contains: JavaHookData, JAVA_HOOK_REGISTRY, CURRENT_HOOK_* globals,
//! helper functions, dispatch_call!, js_call_original, java_hook_callback,
//! replacedMethods mapping (set/get/delete).

use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::callback_util::{
    ensure_registry_initialized, invoke_hook_callback_common,
    BiMap,
};
use crate::jsapi::console::output_message;
use crate::value::JSValue;
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::jni_core::*;

// ============================================================================
// Hook registry
// ============================================================================

/// Hook 类型：统一 Clone+Replace 策略
/// 所有回调统一 JNI 调用约定: x0=JNIEnv*, x1=this/jclass, x2+=args
pub(super) enum HookType {
    /// Unified replacement hook
    /// - replacement_addr: heap-allocated replacement ArtMethod (native, jniCode=thunk)
    /// - per_method_hook_target: Some(quickCode) for compiled methods (Layer 3 router hook),
    ///   None for shared stub methods (routed via Layer 1/2)
    Replaced {
        replacement_addr: usize,
        per_method_hook_target: Option<u64>,
    },
}

pub(super) struct JavaHookData {
    pub(super) art_method: u64,
    // Frida-style original method state（unhook 时恢复全部字段）
    pub(super) original_access_flags: u32,
    pub(super) original_entry_point: u64,  // quickCode / entry_point_
    pub(super) original_data: u64,         // data_ / jniCode
    // Hook 路径类型
    pub(super) hook_type: HookType,
    // Backup clone for callOriginal (heap, 原始状态副本)
    pub(super) clone_addr: u64,
    // JNI global ref to jclass (for JNI CallNonvirtual/Static calls)
    pub(super) class_global_ref: usize,
    // Return type char from JNI signature: b'V', b'I', b'J', b'Z', b'L', etc.
    pub(super) return_type: u8,
    // Full return type descriptor from signature (e.g. "V", "I", "Ljava/lang/String;", "[B")
    pub(super) return_type_sig: String,
    // JS callback info
    pub(super) ctx: usize,
    pub(super) callback_bytes: [u8; 16],
    pub(super) method_key: String, // "class.method.sig" for lookup
    pub(super) is_static: bool,
    pub(super) param_count: usize,
    // Per-parameter JNI type descriptors (e.g. ["I", "Ljava/lang/String;", "[B"])
    pub(super) param_types: Vec<String>,
    // Hooked class name (dot notation, for wrapping object args)
    pub(super) class_name: String,
}

unsafe impl Send for JavaHookData {}
unsafe impl Sync for JavaHookData {}

/// Global Java hook registry keyed by art_method address
pub(super) static JAVA_HOOK_REGISTRY: Mutex<Option<HashMap<u64, JavaHookData>>> = Mutex::new(None);

// Callback state globals — set before JS_Call in java_hook_callback, read by js_call_original.
// Protected by JS_ENGINE lock (single-threaded JS execution). Use atomics to avoid UB from
// static mut in multi-threaded context.
pub(super) static CURRENT_HOOK_CTX_PTR: AtomicUsize = AtomicUsize::new(0);
pub(super) static CURRENT_HOOK_ART_METHOD: AtomicU64 = AtomicU64::new(0);

/// Parse JNI signature to extract the return type character.
/// "(II)V" → b'V', "(Ljava/lang/String;)Ljava/lang/Object;" → b'L'
pub(super) fn get_return_type_from_sig(sig: &str) -> u8 {
    if let Some(pos) = sig.rfind(')') {
        let ret = &sig[pos + 1..];
        match ret.as_bytes().first() {
            Some(&c) => c,
            None => b'V',
        }
    } else {
        b'V'
    }
}

/// Extract the full return type descriptor from a JNI method signature.
/// "(II)V" → "V", "(I)Ljava/lang/String;" → "Ljava/lang/String;", "()[B" → "[B"
pub(super) fn get_return_type_sig(sig: &str) -> String {
    if let Some(pos) = sig.rfind(')') {
        sig[pos + 1..].to_string()
    } else {
        "V".to_string()
    }
}

pub(super) fn init_java_registry() {
    ensure_registry_initialized(&JAVA_HOOK_REGISTRY);
}

/// Build a unique key string for method lookup
pub(super) fn method_key(class: &str, method: &str, sig: &str) -> String {
    format!("{}.{}{}", class, method, sig)
}

/// Iterate over JNI parameter type boundaries in a signature string.
/// Calls `visitor(start, end)` for each parameter's byte range within the '(' ... ')'.
fn for_each_jni_param(sig: &str, mut visitor: impl FnMut(usize, usize)) {
    let bytes = sig.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i] != b'(' { i += 1; }
    i += 1; // skip '('
    while i < bytes.len() && bytes[i] != b')' {
        let start = i;
        match bytes[i] {
            b'L' => {
                while i < bytes.len() && bytes[i] != b';' { i += 1; }
                i += 1; // skip ';'
            }
            b'[' => {
                while i < bytes.len() && bytes[i] == b'[' { i += 1; }
                if i < bytes.len() && bytes[i] == b'L' {
                    while i < bytes.len() && bytes[i] != b';' { i += 1; }
                    i += 1;
                } else {
                    i += 1; // primitive element
                }
            }
            _ => i += 1, // primitive
        }
        visitor(start, i);
    }
}

/// Count the number of parameters in a JNI method signature.
/// "(II)V" → 2, "(Ljava/lang/String;I)V" → 2, "()V" → 0
pub(super) fn count_jni_params(sig: &str) -> usize {
    let mut count = 0;
    for_each_jni_param(sig, |_, _| count += 1);
    count
}

/// Parse a JNI method signature into individual parameter type descriptors.
/// "(ILjava/lang/String;[B)V" → ["I", "Ljava/lang/String;", "[B"]
pub(super) fn parse_jni_param_types(sig: &str) -> Vec<String> {
    let bytes = sig.as_bytes();
    let mut result = Vec::new();
    for_each_jni_param(sig, |start, end| {
        result.push(String::from_utf8_lossy(&bytes[start..end]).to_string());
    });
    result
}

// ============================================================================
// ARM64 JNI calling convention helpers
// ============================================================================

/// 判断 JNI 类型签名是否表示浮点类型 (float/double)
#[inline]
fn is_floating_point_type(sig: Option<&str>) -> bool {
    matches!(sig, Some(s) if s.starts_with('F') || s.starts_with('D'))
}

/// 从 HookContext 中按 ARM64 JNI 调用约定提取单个参数值。
///
/// ARM64 JNI: GP 寄存器 (x2-x7) 和 FP 寄存器 (d0-d7) 有独立计数器。
/// 返回 (gp_value, fp_value) — 只有一个有意义。
#[inline]
unsafe fn extract_jni_arg(
    hook_ctx: &hook_ffi::HookContext,
    is_fp: bool,
    gp_index: &mut usize,
    fp_index: &mut usize,
) -> (u64, u64) {
    if is_fp {
        let fp_val = if *fp_index < 8 { hook_ctx.d[*fp_index] } else { 0u64 };
        *fp_index += 1;
        (0u64, fp_val)
    } else {
        let gp_val = if *gp_index < 6 {
            hook_ctx.x[2 + *gp_index]
        } else {
            let sp = hook_ctx.sp as usize;
            *((sp + (*gp_index - 6) * 8) as *const u64)
        };
        *gp_index += 1;
        (gp_val, 0u64)
    }
}

// ============================================================================
// callOriginal() — JS CFunction invoked from user's hook callback
// ============================================================================

/// Dispatch a JNI call via either static or nonvirtual variant, based on `$is_static`.
/// Consolidates the static/instance arms into one match expression.
macro_rules! dispatch_call {
    ($env:expr, $static_idx:expr, $nonvirt_idx:expr,
     $cls:expr, $this:expr, $mid:expr, $args:expr, $is_static:expr, $ret_ty:ty) => {{
        if $is_static {
            type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> $ret_ty;
            let f: F = jni_fn!($env, F, $static_idx);
            f($env, $cls, $mid, $args)
        } else {
            type F = unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void, *const std::ffi::c_void) -> $ret_ty;
            let f: F = jni_fn!($env, F, $nonvirt_idx);
            f($env, $this, $cls, $mid, $args)
        }
    }};
}

/// Dispatch + check exception + convert result to JSValue.
/// 将 dispatch_call、jni_check_exc 和 JSValue 转换统一为单个宏调用。
macro_rules! dispatch_and_convert {
    // 非 void 原始类型: dispatch → check exc → convert to JSValue
    ($env:expr, $static_idx:expr, $nonvirt_idx:expr,
     $cls:expr, $this:expr, $mid:expr, $args:expr, $is_static:expr,
     $ret_ty:ty, $convert:expr) => {{
        let ret: $ret_ty = dispatch_call!($env, $static_idx, $nonvirt_idx,
                                          $cls, $this, $mid, $args, $is_static, $ret_ty);
        jni_check_exc($env);
        $convert(ret)
    }};
}

/// Convert a JS value to a JNI jvalue (u64) based on the parameter type descriptor.
///
/// Handles: primitives (Z/B/C/S/I/J/F/D), String (JS string → NewStringUTF),
/// objects ({__jptr} or Proxy → extract raw pointer), BigUint64 (raw pointer),
/// null/undefined → 0.
unsafe fn marshal_js_to_jvalue(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    val: JSValue,
    type_sig: Option<&str>,
) -> u64 {
    if val.is_null() || val.is_undefined() {
        return 0;
    }

    let sig = match type_sig {
        Some(s) if !s.is_empty() => s,
        _ => {
            // No type info — try number or bigint
            if let Some(v) = val.to_u64(ctx) { return v; }
            if let Some(v) = val.to_i64(ctx) { return v as u64; }
            return 0;
        }
    };

    match sig.as_bytes()[0] {
        b'Z' => {
            if let Some(b) = val.to_bool() { b as u64 }
            else if let Some(n) = val.to_i64(ctx) { (n != 0) as u64 }
            else { 0 }
        }
        b'B' | b'S' | b'I' => {
            if let Some(n) = val.to_i64(ctx) { n as u64 }
            else { 0 }
        }
        b'C' => {
            // char: JS string (first char) or number
            if let Some(s) = val.to_string(ctx) {
                s.chars().next().map(|c| c as u64).unwrap_or(0)
            } else if let Some(n) = val.to_i64(ctx) {
                n as u64
            } else { 0 }
        }
        b'J' => {
            if let Some(v) = val.to_u64(ctx) { v }
            else if let Some(v) = val.to_i64(ctx) { v as u64 }
            else { 0 }
        }
        b'F' => {
            if let Some(f) = val.to_float() {
                (f as f32).to_bits() as u64
            } else { 0 }
        }
        b'D' => {
            if let Some(f) = val.to_float() {
                f.to_bits()
            } else { 0 }
        }
        b'L' | b'[' => {
            // JS string → NewStringUTF (must check before to_u64, which coerces strings to NaN→0)
            if val.is_string() {
                if sig == "Ljava/lang/String;" {
                    if let Some(s) = val.to_string(ctx) {
                        let cstr = match CString::new(s) {
                            Ok(c) => c,
                            Err(_) => return 0,
                        };
                        let new_str: NewStringUtfFn = jni_fn!(env, NewStringUtfFn, JNI_NEW_STRING_UTF);
                        let jstr = new_str(env, cstr.as_ptr());
                        return jstr as u64;
                    }
                }
                // Non-String object param with string value — toString won't help, return 0
                return 0;
            }
            // JS object → try __jptr property (Proxy-wrapped or {__jptr, __jclass})
            if val.is_object() {
                let jptr_val = val.get_property(ctx, "__jptr");
                if !jptr_val.is_undefined() && !jptr_val.is_null() {
                    let result = jptr_val.to_u64(ctx).unwrap_or(0);
                    jptr_val.free(ctx);
                    return result;
                }
                jptr_val.free(ctx);
            }
            // BigUint64 or number (raw jobject pointer)
            if let Some(v) = val.to_u64(ctx) {
                return v;
            }
            0
        }
        _ => {
            if let Some(v) = val.to_u64(ctx) { v }
            else if let Some(v) = val.to_i64(ctx) { v as u64 }
            else { 0 }
        }
    }
}

/// Invoke cloned ArtMethod via JNI using provided jvalue args.
///
/// Shared by `js_call_original` (JS callback) and fallback path (JS engine busy).
/// Returns the raw u64 return value for writing to HookContext.x[0].
/// For void methods, returns 0.
unsafe fn invoke_clone_jni(
    env: JniEnv,
    art_method_addr: u64,
    clone_addr: u64,
    class_global_ref: usize,
    this_obj: u64,
    return_type: u8,
    is_static: bool,
    jargs_ptr: *const std::ffi::c_void,
) -> u64 {
    // Sync declaring_class_ (offset 0, 4B GcRoot): original → clone
    let declaring_class = std::ptr::read_volatile(art_method_addr as *const u32);
    std::ptr::write_volatile(clone_addr as *mut u32, declaring_class);
    jni_check_exc(env);

    let clone_mid = clone_addr as *mut std::ffi::c_void;
    let cls = class_global_ref as *mut std::ffi::c_void;
    let this_ptr = this_obj as *mut std::ffi::c_void;

    match return_type {
        b'V' => {
            dispatch_call!(env, JNI_CALL_STATIC_VOID_METHOD_A, JNI_CALL_NONVIRTUAL_VOID_METHOD_A,
                           cls, this_ptr, clone_mid, jargs_ptr, is_static, ());
            jni_check_exc(env);
            0
        }
        b'Z' => {
            let ret: u8 = dispatch_call!(env, JNI_CALL_STATIC_BOOLEAN_METHOD_A, JNI_CALL_NONVIRTUAL_BOOLEAN_METHOD_A,
                                          cls, this_ptr, clone_mid, jargs_ptr, is_static, u8);
            jni_check_exc(env);
            ret as u64
        }
        b'I' | b'B' | b'C' | b'S' => {
            let ret: i32 = dispatch_call!(env, JNI_CALL_STATIC_INT_METHOD_A, JNI_CALL_NONVIRTUAL_INT_METHOD_A,
                                           cls, this_ptr, clone_mid, jargs_ptr, is_static, i32);
            jni_check_exc(env);
            ret as u64
        }
        b'J' => {
            let ret: i64 = dispatch_call!(env, JNI_CALL_STATIC_LONG_METHOD_A, JNI_CALL_NONVIRTUAL_LONG_METHOD_A,
                                           cls, this_ptr, clone_mid, jargs_ptr, is_static, i64);
            jni_check_exc(env);
            ret as u64
        }
        b'F' => {
            let ret: f32 = dispatch_call!(env, JNI_CALL_STATIC_FLOAT_METHOD_A, JNI_CALL_NONVIRTUAL_FLOAT_METHOD_A,
                                           cls, this_ptr, clone_mid, jargs_ptr, is_static, f32);
            jni_check_exc(env);
            ret.to_bits() as u64
        }
        b'D' => {
            let ret: f64 = dispatch_call!(env, JNI_CALL_STATIC_DOUBLE_METHOD_A, JNI_CALL_NONVIRTUAL_DOUBLE_METHOD_A,
                                           cls, this_ptr, clone_mid, jargs_ptr, is_static, f64);
            jni_check_exc(env);
            ret.to_bits()
        }
        b'L' | b'[' => {
            let ret: *mut std::ffi::c_void = dispatch_call!(env, JNI_CALL_STATIC_OBJECT_METHOD_A, JNI_CALL_NONVIRTUAL_OBJECT_METHOD_A,
                                                            cls, this_ptr, clone_mid, jargs_ptr, is_static, *mut std::ffi::c_void);
            jni_check_exc(env);
            ret as u64
        }
        _ => 0,
    }
}

/// Build jvalue args from HookContext registers (ARM64 JNI calling convention).
unsafe fn build_jargs_from_registers(
    hook_ctx: &hook_ffi::HookContext,
    param_count: usize,
    param_types: &[String],
) -> Vec<u64> {
    let mut jargs: Vec<u64> = Vec::with_capacity(param_count);
    let mut gp_index: usize = 0;
    let mut fp_index: usize = 0;
    for i in 0..param_count {
        let type_sig = param_types.get(i).map(|s| s.as_str());
        let (gp_val, fp_val) = extract_jni_arg(hook_ctx, is_floating_point_type(type_sig), &mut gp_index, &mut fp_index);
        jargs.push(if is_floating_point_type(type_sig) { fp_val } else { gp_val });
    }
    jargs
}

/// JS CFunction: ctx.callOriginal() or ctx.callOriginal(arg0, arg1, ...)
///
/// No arguments: invokes the clone with the original register arguments.
/// With arguments: invokes the clone with user-specified arguments (JS → jvalue conversion).
///
/// Invokes the cloned ArtMethod via JNI CallNonvirtual*MethodA / CallStatic*MethodA.
/// Returns the method's return value as a JS value.
///
/// Must be called from within a java_hook_callback (reads CURRENT_HOOK_* globals).
unsafe extern "C" fn js_call_original(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let art_method_addr = CURRENT_HOOK_ART_METHOD.load(Ordering::Relaxed);
    let ctx_ptr = CURRENT_HOOK_CTX_PTR.load(Ordering::Relaxed) as *mut hook_ffi::HookContext;
    if ctx_ptr.is_null() || art_method_addr == 0 {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"callOriginal() can only be called inside a hook callback\0".as_ptr() as *const _,
        );
    }

    // Look up hook data for clone info
    let (clone_addr, class_global_ref, return_type, return_type_sig, param_count, is_static, param_types) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => {
                return ffi::JS_ThrowInternalError(
                    ctx,
                    b"callOriginal: hook registry not initialized\0".as_ptr() as *const _,
                );
            }
        };
        let data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => {
                return ffi::JS_ThrowInternalError(
                    ctx,
                    b"callOriginal: hook data not found\0".as_ptr() as *const _,
                );
            }
        };
        (data.clone_addr, data.class_global_ref, data.return_type,
         data.return_type_sig.clone(),
         data.param_count, data.is_static,
         data.param_types.clone())
    }; // lock released

    if clone_addr == 0 {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"callOriginal: no ArtMethod clone available\0".as_ptr() as *const _,
        );
    }

    let hook_ctx = &*ctx_ptr;

    // Unified JNI calling convention: x0=JNIEnv*, x1=this/class, x2+=args
    let env: JniEnv = {
        let e = hook_ctx.x[0] as JniEnv;
        if e.is_null() {
            return ffi::JS_ThrowInternalError(
                ctx,
                b"callOriginal: JNIEnv* is null\0".as_ptr() as *const _,
            );
        }
        e
    };

    // Build jvalue args: from user-specified JS args (if provided), or from registers.
    let jargs = if _argc > 0 && !_argv.is_null() {
        // User-specified arguments: convert JS values → jvalue
        let mut args: Vec<u64> = Vec::with_capacity(param_count);
        for i in 0..param_count {
            let type_sig = param_types.get(i).map(|s| s.as_str());
            if (i as i32) < _argc {
                let js_arg = JSValue(*_argv.add(i));
                args.push(marshal_js_to_jvalue(ctx, env, js_arg, type_sig));
            } else {
                // 不足的参数用原始寄存器值补齐
                let mut gp = i;
                let mut fp = i;
                let (gp_val, fp_val) = extract_jni_arg(hook_ctx, is_floating_point_type(type_sig), &mut gp, &mut fp);
                args.push(if is_floating_point_type(type_sig) { fp_val } else { gp_val });
            }
        }
        args
    } else {
        // No arguments: use original register values
        build_jargs_from_registers(hook_ctx, param_count, &param_types)
    };
    let jargs_ptr = if param_count > 0 {
        jargs.as_ptr() as *const std::ffi::c_void
    } else {
        std::ptr::null()
    };

    // Invoke clone via shared JNI helper
    let ret_raw = invoke_clone_jni(
        env, art_method_addr, clone_addr, class_global_ref,
        hook_ctx.x[1], return_type, is_static, jargs_ptr,
    );

    // Convert raw return value to JS value
    match return_type {
        b'V' => ffi::qjs_undefined(),
        b'Z' => JSValue::bool(ret_raw != 0).raw(),
        b'I' | b'B' | b'C' | b'S' => JSValue::int(ret_raw as i32).raw(),
        b'J' => ffi::JS_NewBigUint64(ctx, ret_raw),
        b'F' => JSValue::float(f32::from_bits(ret_raw as u32) as f64).raw(),
        b'D' => JSValue::float(f64::from_bits(ret_raw)).raw(),
        b'L' | b'[' => {
            if ret_raw == 0 {
                ffi::qjs_null()
            } else {
                // Convert to readable JS value (String → JS string, objects → wrapped)
                // using the same logic as arg marshalling.
                marshal_jni_arg_to_js(ctx, env, ret_raw, 0, Some(&return_type_sig))
            }
        }
        _ => ffi::qjs_undefined(),
    }
}

// ============================================================================
// Argument marshalling — convert raw JNI register values to JS values
// ============================================================================

/// Convert a raw JNI argument (from register) to a JS value based on its JNI type descriptor.
///
/// Primitive types become JS numbers/booleans/bigints.
/// String objects become JS strings (read via GetStringUTFChars).
/// Other objects become wrapped `{__jptr, __jclass}` for Proxy-based field access.
/// Falls back to BigUint64 if type info is unavailable.
///
/// `fp_raw`: value from the corresponding d-register (for float/double args).
unsafe fn marshal_jni_arg_to_js(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    raw: u64,
    fp_raw: u64,
    type_sig: Option<&str>,
) -> ffi::JSValue {
    let sig = match type_sig {
        Some(s) if !s.is_empty() => s,
        _ => return ffi::JS_NewBigUint64(ctx, raw),
    };

    match sig.as_bytes()[0] {
        b'Z' => JSValue::bool(raw != 0).raw(),
        b'B' => JSValue::int(raw as i8 as i32).raw(),
        b'C' => {
            // char → JS string (single UTF-16 character)
            let ch = std::char::from_u32(raw as u32).unwrap_or('\0');
            let s = ch.to_string();
            JSValue::string(ctx, &s).raw()
        }
        b'S' => JSValue::int(raw as i16 as i32).raw(),
        b'I' => JSValue::int(raw as i32).raw(),
        b'J' => ffi::JS_NewBigUint64(ctx, raw),
        b'F' => {
            // ARM64 ABI: floats are passed in d0-d7 (FP registers).
            // fp_raw comes from HookContext.d[fp_index].
            let f = f32::from_bits(fp_raw as u32);
            JSValue::float(f as f64).raw()
        }
        b'D' => {
            // ARM64 ABI: doubles are passed in d0-d7 (FP registers).
            // fp_raw comes from HookContext.d[fp_index].
            let d = f64::from_bits(fp_raw);
            JSValue::float(d).raw()
        }
        b'L' | b'[' => {
            // Object or array — raw is a jobject local ref
            let obj = raw as *mut std::ffi::c_void;
            if obj.is_null() {
                return ffi::qjs_null();
            }

            // String → read as JS string
            if sig == "Ljava/lang/String;" {
                let get_str: GetStringUtfCharsFn =
                    jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
                let rel_str: ReleaseStringUtfCharsFn =
                    jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);

                let chars = get_str(env, obj, std::ptr::null_mut());
                if !chars.is_null() {
                    let s = std::ffi::CStr::from_ptr(chars)
                        .to_string_lossy()
                        .to_string();
                    rel_str(env, obj, chars);
                    return JSValue::string(ctx, &s).raw();
                }
                // GetStringUTFChars failed — fall through to wrapped object
                jni_check_exc(env);
            }

            // Other object → wrap as {__jptr, __jclass} for Proxy field access
            let wrapper = ffi::JS_NewObject(ctx);
            let wrapper_val = JSValue(wrapper);

            let ptr_val = ffi::JS_NewBigUint64(ctx, raw);
            wrapper_val.set_property(ctx, "__jptr", JSValue(ptr_val));

            // Extract class name from signature: "Ljava/lang/Foo;" → "java.lang.Foo"
            let type_name = if sig.starts_with('L') && sig.ends_with(';') {
                sig[1..sig.len() - 1].replace('/', ".")
            } else {
                // Array or unknown — use raw signature
                sig.replace('/', ".")
            };
            let cls_val = JSValue::string(ctx, &type_name);
            wrapper_val.set_property(ctx, "__jclass", cls_val);

            wrapper
        }
        _ => ffi::JS_NewBigUint64(ctx, raw),
    }
}

// ============================================================================
// Hook callback (runs in hooked thread, called by ART JNI trampoline)
// ============================================================================

/// Callback invoked by the native hook trampoline when a hooked Java method is called.
/// After "replace with native", ART's JNI trampoline calls our thunk which calls this.
///
/// HookContext contains JNI calling convention registers:
///   x0 = JNIEnv*, x1 = jobject this (instance) or jclass (static), x2-x7 = Java args
///
/// user_data = ArtMethod* address (used for registry lookup).
pub(super) unsafe extern "C" fn java_hook_callback(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    // user_data is ArtMethod* address (used as registry key)
    let art_method_addr = user_data as u64;

    // Copy callback data then release lock before QuickJS operations.
    // Also extract clone info for fallback callOriginal when JS engine is busy.
    let (ctx_usize, callback_bytes, is_static, param_count, return_type, return_type_sig,
         param_types, clone_addr, class_global_ref) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(_) => {
                // Lock poisoned during cleanup — zero x0 to prevent returning garbage
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => {
                // Registry taken during cleanup — zero x0 to prevent returning JNIEnv* as object
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        let hook_data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => {
                // Hook data removed during cleanup — zero x0
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        (hook_data.ctx, hook_data.callback_bytes, hook_data.is_static,
         hook_data.param_count, hook_data.return_type,
         hook_data.return_type_sig.clone(),
         hook_data.param_types.clone(),
         hook_data.clone_addr, hook_data.class_global_ref)
    }; // lock released

    // Set callback state globals for js_call_original
    CURRENT_HOOK_CTX_PTR.store(ctx_ptr as usize, Ordering::Relaxed);
    CURRENT_HOOK_ART_METHOD.store(art_method_addr, Ordering::Relaxed);

    // Push local frame to protect JNI local refs from overflowing the table.
    // Each marshal_jni_arg_to_js call may create local refs (GetStringUTFChars, NewObject, etc.).
    let hook_ctx_env: JniEnv = (*ctx_ptr).x[0] as JniEnv;
    let has_local_frame = if !hook_ctx_env.is_null() {
        let push_frame: PushLocalFrameFn = jni_fn!(hook_ctx_env, PushLocalFrameFn, JNI_PUSH_LOCAL_FRAME);
        push_frame(hook_ctx_env, (2 + param_count * 2) as i32) == 0
    } else {
        false
    };

    // Track whether handle_result was called (false if JS exception occurred)
    let mut result_was_set = false;

    invoke_hook_callback_common(
        ctx_usize,
        &callback_bytes,
        "java hook",
        art_method_addr,
        // 构建 JS 上下文对象：thisObj, args[], env, callOriginal()
        |ctx| {
            let js_ctx = ffi::JS_NewObject(ctx);
            let hook_ctx = &*ctx_ptr;
            let env: JniEnv = hook_ctx.x[0] as JniEnv;

            // thisObj for instance methods (x1 = jobject this)
            if !is_static {
                let val = ffi::JS_NewBigUint64(ctx, hook_ctx.x[1]);
                JSValue(js_ctx).set_property(ctx, "thisObj", JSValue(val));
            }

            // args[] — ARM64 JNI calling convention (GP x2-x7, FP d0-d7 independent)
            {
                let arr = ffi::JS_NewArray(ctx);
                let mut gp_index: usize = 0;
                let mut fp_index: usize = 0;
                for i in 0..param_count {
                    let type_sig = param_types.get(i).map(|s| s.as_str());
                    let (raw, fp_raw) = extract_jni_arg(hook_ctx, is_floating_point_type(type_sig), &mut gp_index, &mut fp_index);
                    let val = marshal_jni_arg_to_js(ctx, env, raw, fp_raw, type_sig);
                    ffi::JS_SetPropertyUint32(ctx, arr, i as u32, val);
                }
                JSValue(js_ctx).set_property(ctx, "args", JSValue(arr));
            }

            // env (JNIEnv* — from x0)
            {
                let val = ffi::JS_NewBigUint64(ctx, hook_ctx.x[0]);
                JSValue(js_ctx).set_property(ctx, "env", JSValue(val));
            }

            // callOriginal()
            {
                let cname = CString::new("callOriginal").unwrap();
                let func_val = ffi::qjs_new_cfunction(ctx, Some(js_call_original), cname.as_ptr(), 0);
                JSValue(js_ctx).set_property(ctx, "callOriginal", JSValue(func_val));
            }

            js_ctx
        },
        // 处理返回值：根据 return_type 将 JS 返回值写入 HookContext.x[0]
        |ctx, _js_ctx, result| {
            result_was_set = true;
            if return_type != b'V' {
                let result_val = JSValue(result);
                let ret_u64 = match return_type {
                    b'F' => {
                        if let Some(f) = result_val.to_float() {
                            (f as f32).to_bits() as u64
                        } else {
                            0u64
                        }
                    }
                    b'D' => {
                        if let Some(f) = result_val.to_float() {
                            f.to_bits()
                        } else {
                            0u64
                        }
                    }
                    b'L' | b'[' => {
                        // Object/array return: marshal JS value back to JNI ref.
                        // Handles: JS string → NewStringUTF, __jptr wrapper → raw ref,
                        // BigUint64 → raw ref, null/undefined → 0.
                        let env: JniEnv = hook_ctx_env;
                        if !env.is_null() {
                            marshal_js_to_jvalue(ctx, env, result_val, Some(&return_type_sig))
                        } else {
                            result_val.to_u64(ctx).unwrap_or(0)
                        }
                    }
                    _ => {
                        if let Some(v) = result_val.to_u64(ctx) {
                            v
                        } else if let Some(v) = result_val.to_i64(ctx) {
                            v as u64
                        } else {
                            0u64
                        }
                    }
                };
                (*ctx_ptr).x[0] = ret_u64;
            }
        },
    );

    // Fallback: if JS callback was skipped (engine busy) or threw an exception,
    // handle_result was NOT called. x[0] still contains JNIEnv* (the entry value).
    // For non-void methods, ART's GenericJniMethodEnd would interpret JNIEnv* as a
    // return value — for L/[ types, DecodeJObject(JNIEnv*) crashes.
    // Fix: call original method via JNI to get a valid return value.
    if !result_was_set && return_type != b'V' {
        let hook_ctx = &*ctx_ptr;
        let env: JniEnv = hook_ctx.x[0] as JniEnv;
        if !env.is_null() && clone_addr != 0 {
            let jargs = build_jargs_from_registers(hook_ctx, param_count, &param_types);
            let jargs_ptr = if param_count > 0 {
                jargs.as_ptr() as *const std::ffi::c_void
            } else {
                std::ptr::null()
            };
            (*ctx_ptr).x[0] = invoke_clone_jni(
                env, art_method_addr, clone_addr, class_global_ref,
                hook_ctx.x[1], return_type, is_static, jargs_ptr,
            );
        } else {
            (*ctx_ptr).x[0] = 0;
        }
    }

    // Always PopLocalFrame to keep IRT segments balanced.
    // For object returns (L/[): PopLocalFrame(env, ret_obj) transfers the local ref
    // to the outer frame (ART's JNI transition frame) so GenericJniMethodEnd can find it.
    // For other types: PopLocalFrame(env, null) just cleans up.
    if has_local_frame && !hook_ctx_env.is_null() {
        let pop_frame: PopLocalFrameFn = jni_fn!(hook_ctx_env, PopLocalFrameFn, JNI_POP_LOCAL_FRAME);
        if return_type == b'L' || return_type == b'[' {
            let ret_obj = (*ctx_ptr).x[0] as *mut std::ffi::c_void;
            let preserved = pop_frame(hook_ctx_env, ret_obj);
            (*ctx_ptr).x[0] = preserved as u64;
        } else {
            pop_frame(hook_ctx_env, std::ptr::null_mut());
        }
    }

    // Clear callback state globals
    CURRENT_HOOK_CTX_PTR.store(0, Ordering::Relaxed);
    CURRENT_HOOK_ART_METHOD.store(0, Ordering::Relaxed);
}

// ============================================================================
// replacedMethods — 双向映射 original↔replacement ArtMethod
// ============================================================================
//
// 用于 artController 全局 DoCall hook 回调中查找 replacement。
// artController hooks ART 的 DoCall 函数（解释器路径），在 on_enter 回调中
// 通过此映射将 x0 (ArtMethod*) 从 original 替换为 replacement。
// 所有被 hook 方法均通过 per-method deoptimize 强制走解释器 → DoCall 路径。

/// 双向映射 original ArtMethod ↔ replacement ArtMethod
static REPLACED_METHODS: BiMap = BiMap::new();

/// 注册 original → replacement 映射（双向 + C 侧内联查表）
pub(super) fn set_replacement_method(original: u64, replacement: u64) {
    REPLACED_METHODS.init();
    REPLACED_METHODS.insert(original, replacement);
    // 同步到 C 侧内联查表 (thunk 直接扫描，无需 Mutex+HashMap)
    unsafe {
        hook_ffi::hook_art_router_table_add(original, replacement);
    }
}

/// 查找 original 对应的 replacement（如果已注册）
pub(super) fn get_replacement_method(original: u64) -> Option<u64> {
    REPLACED_METHODS.get_forward(original)
}

/// 删除 original → replacement 映射（双向 + C 侧内联查表）
pub(super) fn delete_replacement_method(original: u64) {
    REPLACED_METHODS.remove_by_forward(original);
    // 同步到 C 侧内联查表
    unsafe {
        hook_ffi::hook_art_router_table_remove(original);
    }
}

/// 检查给定地址是否为 replacement ArtMethod
#[allow(dead_code)]
pub(super) fn is_replacement_method(method: u64) -> bool {
    REPLACED_METHODS.contains_reverse(method)
}

// NOTE: art_router_fn has been removed — routing is now done via inline
// g_art_router_table scan in the C-side thunk (no function call needed).

