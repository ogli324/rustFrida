//! JS API: Java.getField / Java._getFieldAuto + shared field-value reader

use crate::ffi;
use crate::value::JSValue;
use std::ffi::CString;

use super::jni_core::*;
use super::reflect::*;
use super::art_method::*;
use super::callback::*;

// ============================================================================
// Shared field-value reader (used by getField and _getFieldAuto)
// ============================================================================

pub(super) enum ObjectFieldMode {
    RawPointer,
    WrappedProxy { type_name: String },
}

/// Read a single field value from a JNI object (or class for static fields),
/// dispatching on the JNI type signature.
/// For 'L'/'[' fields: String fields become JS strings; other objects are handled
/// according to `mode` (RawPointer returns BigUint64, WrappedProxy returns {__jptr, __jclass}).
///
/// `obj_or_cls`: for instance fields, this is the JNI local ref to the object;
///               for static fields, this is the jclass.
unsafe fn read_field_value(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    obj_or_cls: *mut std::ffi::c_void,
    field_id: *mut std::ffi::c_void,
    jni_sig: &str,
    is_static: bool,
    mode: ObjectFieldMode,
) -> ffi::JSValue {
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let sig_bytes = jni_sig.as_bytes();
    match sig_bytes.first() {
        Some(b'Z') => {
            if is_static {
                let f: GetStaticBooleanFieldFn = jni_fn!(env, GetStaticBooleanFieldFn, JNI_GET_STATIC_BOOLEAN_FIELD);
                JSValue::bool(f(env, obj_or_cls, field_id) != 0).raw()
            } else {
                let f: GetBooleanFieldFn = jni_fn!(env, GetBooleanFieldFn, JNI_GET_BOOLEAN_FIELD);
                JSValue::bool(f(env, obj_or_cls, field_id) != 0).raw()
            }
        }
        Some(b'B') => {
            if is_static {
                let f: GetStaticByteFieldFn = jni_fn!(env, GetStaticByteFieldFn, JNI_GET_STATIC_BYTE_FIELD);
                JSValue::int(f(env, obj_or_cls, field_id) as i32).raw()
            } else {
                let f: GetByteFieldFn = jni_fn!(env, GetByteFieldFn, JNI_GET_BYTE_FIELD);
                JSValue::int(f(env, obj_or_cls, field_id) as i32).raw()
            }
        }
        Some(b'C') => {
            if is_static {
                let f: GetStaticCharFieldFn = jni_fn!(env, GetStaticCharFieldFn, JNI_GET_STATIC_CHAR_FIELD);
                JSValue::int(f(env, obj_or_cls, field_id) as i32).raw()
            } else {
                let f: GetCharFieldFn = jni_fn!(env, GetCharFieldFn, JNI_GET_CHAR_FIELD);
                JSValue::int(f(env, obj_or_cls, field_id) as i32).raw()
            }
        }
        Some(b'S') => {
            if is_static {
                let f: GetStaticShortFieldFn = jni_fn!(env, GetStaticShortFieldFn, JNI_GET_STATIC_SHORT_FIELD);
                JSValue::int(f(env, obj_or_cls, field_id) as i32).raw()
            } else {
                let f: GetShortFieldFn = jni_fn!(env, GetShortFieldFn, JNI_GET_SHORT_FIELD);
                JSValue::int(f(env, obj_or_cls, field_id) as i32).raw()
            }
        }
        Some(b'I') => {
            if is_static {
                let f: GetStaticIntFieldFn = jni_fn!(env, GetStaticIntFieldFn, JNI_GET_STATIC_INT_FIELD);
                JSValue::int(f(env, obj_or_cls, field_id)).raw()
            } else {
                let f: GetIntFieldFn = jni_fn!(env, GetIntFieldFn, JNI_GET_INT_FIELD);
                JSValue::int(f(env, obj_or_cls, field_id)).raw()
            }
        }
        Some(b'J') => {
            if is_static {
                let f: GetStaticLongFieldFn = jni_fn!(env, GetStaticLongFieldFn, JNI_GET_STATIC_LONG_FIELD);
                ffi::JS_NewBigUint64(ctx, f(env, obj_or_cls, field_id) as u64)
            } else {
                let f: GetLongFieldFn = jni_fn!(env, GetLongFieldFn, JNI_GET_LONG_FIELD);
                ffi::JS_NewBigUint64(ctx, f(env, obj_or_cls, field_id) as u64)
            }
        }
        Some(b'F') => {
            if is_static {
                let f: GetStaticFloatFieldFn = jni_fn!(env, GetStaticFloatFieldFn, JNI_GET_STATIC_FLOAT_FIELD);
                JSValue::float(f(env, obj_or_cls, field_id) as f64).raw()
            } else {
                let f: GetFloatFieldFn = jni_fn!(env, GetFloatFieldFn, JNI_GET_FLOAT_FIELD);
                JSValue::float(f(env, obj_or_cls, field_id) as f64).raw()
            }
        }
        Some(b'D') => {
            if is_static {
                let f: GetStaticDoubleFieldFn = jni_fn!(env, GetStaticDoubleFieldFn, JNI_GET_STATIC_DOUBLE_FIELD);
                JSValue::float(f(env, obj_or_cls, field_id)).raw()
            } else {
                let f: GetDoubleFieldFn = jni_fn!(env, GetDoubleFieldFn, JNI_GET_DOUBLE_FIELD);
                JSValue::float(f(env, obj_or_cls, field_id)).raw()
            }
        }
        Some(b'L') | Some(b'[') => {
            let obj_val = if is_static {
                let f: GetStaticObjectFieldFn = jni_fn!(env, GetStaticObjectFieldFn, JNI_GET_STATIC_OBJECT_FIELD);
                f(env, obj_or_cls, field_id)
            } else {
                let f: GetObjectFieldFn = jni_fn!(env, GetObjectFieldFn, JNI_GET_OBJECT_FIELD);
                f(env, obj_or_cls, field_id)
            };

            if obj_val.is_null() {
                return ffi::qjs_null();
            }

            // Check if String type
            if jni_sig == "Ljava/lang/String;" {
                let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
                let rel_str: ReleaseStringUtfCharsFn = jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);

                let chars = get_str(env, obj_val, std::ptr::null_mut());
                let js_result = if !chars.is_null() {
                    let s = std::ffi::CStr::from_ptr(chars)
                        .to_string_lossy()
                        .to_string();
                    rel_str(env, obj_val, chars);
                    JSValue::string(ctx, &s).raw()
                } else {
                    ffi::qjs_null()
                };
                delete_local_ref(env, obj_val);
                return js_result;
            }

            match mode {
                ObjectFieldMode::RawPointer => {
                    let ptr_val = obj_val as u64;
                    delete_local_ref(env, obj_val);
                    ffi::JS_NewBigUint64(ctx, ptr_val)
                }
                ObjectFieldMode::WrappedProxy { ref type_name } => {
                    // Convert local ref to global ref so it survives beyond this native frame.
                    // Local refs are only valid within the current JNI call; storing a local ref
                    // in a JS object for later use would result in a dangling reference.
                    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
                    let global_ref = new_global_ref(env, obj_val);
                    delete_local_ref(env, obj_val);

                    let wrapper = ffi::JS_NewObject(ctx);
                    let wrapper_val = JSValue(wrapper);

                    let ptr_val = ffi::JS_NewBigUint64(ctx, global_ref as u64);
                    wrapper_val.set_property(ctx, "__jptr", JSValue(ptr_val));

                    let cls_val = JSValue::string(ctx, type_name);
                    wrapper_val.set_property(ctx, "__jclass", cls_val);

                    wrapper
                }
            }
        }
        _ => ffi::qjs_undefined(),
    }
}

// ============================================================================
// JS API: Java.getField(objPtr, className, fieldName, fieldSig)
// ============================================================================

pub(super) unsafe extern "C" fn js_java_get_field(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    use crate::jsapi::ptr::get_native_pointer_addr;

    if argc < 4 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.getField() requires 4 arguments: objPtr, className, fieldName, fieldSig\0"
                .as_ptr() as *const _,
        );
    }

    let obj_arg = JSValue(*argv);
    let class_arg = JSValue(*argv.add(1));
    let method_arg = JSValue(*argv.add(2));
    let sig_arg = JSValue(*argv.add(3));

    // Extract objPtr — try NativePointer first, then BigUint64/Number
    let obj_ptr = if let Some(addr) = get_native_pointer_addr(ctx, obj_arg) {
        addr
    } else if let Some(addr) = obj_arg.to_u64(ctx) {
        addr
    } else {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.getField() first argument must be a pointer (BigUint64/Number/NativePointer)\0"
                .as_ptr() as *const _,
        );
    };

    if obj_ptr == 0 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.getField() objPtr is null\0".as_ptr() as *const _,
        );
    }

    let class_name = match class_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.getField() className must be a string\0".as_ptr() as *const _,
            )
        }
    };

    let field_name = match method_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.getField() fieldName must be a string\0".as_ptr() as *const _,
            )
        }
    };

    let field_sig = match sig_arg.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java.getField() fieldSig must be a string\0".as_ptr() as *const _,
            )
        }
    };

    // Get thread-safe JNIEnv*
    let env = match get_thread_env() {
        Ok(e) => e,
        Err(msg) => {
            let err = CString::new(msg).unwrap();
            return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
        }
    };

    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);
    let get_field_id: GetFieldIdFn = jni_fn!(env, GetFieldIdFn, JNI_GET_FIELD_ID);

    // FindClass — use find_class_safe to support app classes
    let cls = find_class_safe(env, &class_name);
    if cls.is_null() {
        let err = CString::new(format!("FindClass('{}') failed", class_name)).unwrap();
        return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
    }

    // NewLocalRef — wrap raw mirror pointer as a proper JNI local ref
    let local_obj = new_local_ref(env, obj_ptr as *mut std::ffi::c_void);
    if local_obj.is_null() {
        delete_local_ref(env, cls);
        return ffi::JS_ThrowInternalError(
            ctx,
            b"NewLocalRef failed for objPtr\0".as_ptr() as *const _,
        );
    }

    // GetFieldID
    let c_field = match CString::new(field_name.as_str()) {
        Ok(c) => c,
        Err(_) => {
            delete_local_ref(env, local_obj);
            delete_local_ref(env, cls);
            return ffi::JS_ThrowTypeError(
                ctx,
                b"invalid field name\0".as_ptr() as *const _,
            );
        }
    };
    let c_sig = match CString::new(field_sig.as_str()) {
        Ok(c) => c,
        Err(_) => {
            delete_local_ref(env, local_obj);
            delete_local_ref(env, cls);
            return ffi::JS_ThrowTypeError(
                ctx,
                b"invalid field signature\0".as_ptr() as *const _,
            );
        }
    };

    let field_id = get_field_id(env, cls, c_field.as_ptr(), c_sig.as_ptr());
    if field_id.is_null() || jni_check_exc(env) {
        delete_local_ref(env, local_obj);
        delete_local_ref(env, cls);
        let err = CString::new(format!(
            "GetFieldID failed: {}.{} (sig={})",
            class_name, field_name, field_sig
        ))
        .unwrap();
        return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
    }

    // Check for unsupported signature before calling read_field_value
    let sig_first = field_sig.as_bytes().first().copied();
    if !matches!(sig_first, Some(b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' | b'L' | b'[')) {
        delete_local_ref(env, local_obj);
        delete_local_ref(env, cls);
        let err = CString::new(format!("unsupported field signature: {}", field_sig)).unwrap();
        return ffi::JS_ThrowTypeError(ctx, err.as_ptr());
    }

    // Dispatch via shared helper (RawPointer mode — returns BigUint64 for objects)
    // Note: js_java_get_field only supports instance fields (GetFieldID was used above)
    let result = read_field_value(ctx, env, local_obj, field_id, &field_sig, false, ObjectFieldMode::RawPointer);

    // Check for JNI exception after field access
    if jni_check_exc(env) {
        delete_local_ref(env, local_obj);
        delete_local_ref(env, cls);
        let err = CString::new(format!(
            "JNI exception reading field {}.{}",
            class_name, field_name
        ))
        .unwrap();
        return ffi::JS_ThrowInternalError(ctx, err.as_ptr());
    }

    delete_local_ref(env, local_obj);
    delete_local_ref(env, cls);
    result
}

// ============================================================================
// JS API: Java._getFieldAuto(objPtr, className, fieldName)
//   Auto-detects field type via JNI reflection, returns value directly.
//   Returns undefined for missing fields (Proxy-friendly).
//   Lazy caching: if className not in FIELD_CACHE, enumerate on the fly.
//   Runtime class fallback: if field not found in declared type, use
//   GetObjectClass to detect the actual runtime type and retry.
// ============================================================================

/// Try to look up a field in FIELD_CACHE for the given class.
/// Returns (jni_sig, field_id, is_static, type_name) or None if not found.
unsafe fn lookup_field_in_cache(
    class_name: &str,
    field_name: &str,
) -> Option<(String, *mut std::ffi::c_void, bool, String)> {
    let guard = FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let cache = guard.as_ref()?;
    let class_fields = cache.get(class_name)?;
    let info = class_fields.get(field_name)?;
    let tn = match info.jni_sig.as_bytes().first() {
        Some(b'L') => {
            let inner = &info.jni_sig[1..info.jni_sig.len() - 1];
            inner.replace('/', ".")
        }
        _ => String::new(),
    };
    Some((info.jni_sig.clone(), info.field_id, info.is_static, tn))
}

/// Check if a class is already in FIELD_CACHE.
unsafe fn is_class_cached(class_name: &str) -> bool {
    let guard = FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        Some(cache) => cache.contains_key(class_name),
        None => false,
    }
}

/// Get the runtime class name of a JNI object via GetObjectClass + Class.getName().
unsafe fn get_runtime_class_name(env: JniEnv, obj: *mut std::ffi::c_void) -> Option<String> {
    let get_object_class: GetObjectClassFn =
        jni_fn!(env, GetObjectClassFn, JNI_GET_OBJECT_CLASS);
    let delete_local_ref: DeleteLocalRefFn =
        jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let call_obj: CallObjectMethodAFn =
        jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let get_str: GetStringUtfCharsFn =
        jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
    let rel_str: ReleaseStringUtfCharsFn =
        jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);

    let reflect = REFLECT_IDS.get()?;

    let cls_obj = get_object_class(env, obj);
    if cls_obj.is_null() {
        jni_check_exc(env);
        return None;
    }

    let name_jstr = call_obj(env, cls_obj, reflect.class_get_name_mid, std::ptr::null());
    delete_local_ref(env, cls_obj);
    if name_jstr.is_null() {
        jni_check_exc(env);
        return None;
    }

    let chars = get_str(env, name_jstr, std::ptr::null_mut());
    if chars.is_null() {
        delete_local_ref(env, name_jstr);
        jni_check_exc(env);
        return None;
    }
    let name = std::ffi::CStr::from_ptr(chars).to_string_lossy().to_string();
    rel_str(env, name_jstr, chars);
    delete_local_ref(env, name_jstr);
    Some(name)
}

/// Read an instance field given resolved cache info.
unsafe fn read_instance_field(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    obj_ptr: u64,
    jni_sig: &str,
    field_id: *mut std::ffi::c_void,
    type_name: &str,
) -> ffi::JSValue {
    let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let local_obj = new_local_ref(env, obj_ptr as *mut std::ffi::c_void);
    if local_obj.is_null() {
        return ffi::qjs_undefined();
    }

    let mode = ObjectFieldMode::WrappedProxy { type_name: type_name.to_string() };
    let result = read_field_value(ctx, env, local_obj, field_id, jni_sig, false, mode);
    jni_check_exc(env);
    delete_local_ref(env, local_obj);
    result
}

pub(super) unsafe extern "C" fn js_java_get_field_auto(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    use crate::jsapi::ptr::get_native_pointer_addr;

    if argc < 3 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"_getFieldAuto() requires 3 arguments: objPtr, className, fieldName\0".as_ptr()
                as *const _,
        );
    }

    let obj_arg = JSValue(*argv);
    let _class_arg = JSValue(*argv.add(1));
    let field_arg = JSValue(*argv.add(2));

    let field_name = match field_arg.to_string(ctx) {
        Some(s) => s,
        None => return ffi::qjs_undefined(),
    };

    let class_name = match _class_arg.to_string(ctx) {
        Some(s) => s,
        None => return ffi::qjs_undefined(),
    };

    // Extract objPtr
    let obj_ptr = if let Some(addr) = get_native_pointer_addr(ctx, obj_arg) {
        addr
    } else if let Some(addr) = obj_arg.to_u64(ctx) {
        addr
    } else {
        return ffi::qjs_undefined();
    };

    if obj_ptr == 0 {
        return ffi::qjs_null();
    }

    // Get thread-safe JNIEnv*
    let env = match get_thread_env() {
        Ok(e) => e,
        Err(_) => return ffi::qjs_undefined(),
    };

    // Step 1: Lazy cache — if class not yet in FIELD_CACHE, enumerate now
    if !is_class_cached(&class_name) {
        cache_fields_for_class(env, &class_name);
    }

    // Step 2: Try to look up the field in the declared class
    if let Some((jni_sig, field_id, is_static, type_name)) = lookup_field_in_cache(&class_name, &field_name) {
        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
        if is_static {
            let cls = find_class_safe(env, &class_name);
            if cls.is_null() {
                return ffi::qjs_undefined();
            }
            let mode = ObjectFieldMode::WrappedProxy { type_name };
            let result = read_field_value(ctx, env, cls, field_id, &jni_sig, true, mode);
            jni_check_exc(env);
            delete_local_ref(env, cls);
            return result;
        } else {
            return read_instance_field(ctx, env, obj_ptr, &jni_sig, field_id, &type_name);
        }
    }

    // Step 3: Field not found in declared type — try runtime class via GetObjectClass
    let new_local_ref: NewLocalRefFn = jni_fn!(env, NewLocalRefFn, JNI_NEW_LOCAL_REF);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let local_obj = new_local_ref(env, obj_ptr as *mut std::ffi::c_void);
    if local_obj.is_null() {
        return ffi::qjs_undefined();
    }

    let runtime_class = get_runtime_class_name(env, local_obj);
    delete_local_ref(env, local_obj);

    if let Some(ref rt_cls) = runtime_class {
        if rt_cls != &class_name {
            // Lazy cache the runtime class too
            if !is_class_cached(rt_cls) {
                cache_fields_for_class(env, rt_cls);
            }
            if let Some((jni_sig, field_id, is_static, type_name)) = lookup_field_in_cache(rt_cls, &field_name) {
                if is_static {
                    let cls = find_class_safe(env, rt_cls);
                    if cls.is_null() {
                        return ffi::qjs_undefined();
                    }
                    let mode = ObjectFieldMode::WrappedProxy { type_name };
                    let result = read_field_value(ctx, env, cls, field_id, &jni_sig, true, mode);
                    jni_check_exc(env);
                    delete_local_ref(env, cls);
                    return result;
                } else {
                    return read_instance_field(ctx, env, obj_ptr, &jni_sig, field_id, &type_name);
                }
            }
        }
    }

    ffi::qjs_undefined()
}
