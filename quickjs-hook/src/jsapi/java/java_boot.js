// Java.use() API — Frida-compatible syntax for Java method hooking
// Evaluated at engine init after C-level Java.hook/unhook/_methods/_getFieldAuto are registered.
(function() {
    "use strict";
    var _hook = Java.hook;
    var _unhook = Java.unhook;
    var _methods = Java._methods;
    var _getFieldAuto = Java._getFieldAuto;
    var _beginBatch = Java._beginBatch;
    var _endBatch = Java._endBatch;
    delete Java.hook;
    delete Java.unhook;
    delete Java._methods;
    delete Java._getFieldAuto;
    delete Java._beginBatch;
    delete Java._endBatch;

    // Wrap a raw Java object pointer as a Proxy for field access via dot notation.
    // e.g. ctx.thisObj.mTitle reads the mTitle field via JNI reflection.
    // Primitive fields → JS primitives; Object fields → recursively wrapped Proxy.
    function _wrapJavaObj(ptr, cls) {
        var target = {__jptr: ptr, __jclass: cls};
        var handler = {
            get: function(target, prop) {
                if (prop === "__jptr") return target.__jptr;
                if (prop === "__jclass") return target.__jclass;
                if (prop === Symbol.toPrimitive) return function(hint) {
                    return "[JavaObject:" + target.__jclass + "@" + target.__jptr + "]";
                };
                if (typeof prop !== "string") return undefined;
                if (prop === "toString" || prop === "valueOf") return function() {
                    return "[JavaObject:" + target.__jclass + "]";
                };
                if (prop === "$className") return target.__jclass;
                var jptr = target.__jptr;
                var jcls = target.__jclass;
                try {
                    var result = _getFieldAuto(jptr, jcls, prop);
                } catch(e) {
                    console.log("[_wrapJavaObj] _getFieldAuto ERROR: " + e
                        + " ptr=" + jptr + " cls=" + jcls
                        + " prop=" + prop);
                    return undefined;
                }
                // Object fields come back as {__jptr, __jclass} — wrap recursively
                if (result !== null && typeof result === "object"
                    && result.__jptr !== undefined) {
                    return _wrapJavaObj(result.__jptr, result.__jclass);
                }
                return result;
            }
        };
        return new Proxy(target, handler);
    }

    function MethodWrapper(cls, method, sig, cache) {
        this._c = cls;
        this._m = method;
        this._s = sig || null;
        this._cache = cache || null;
    }

    // Convert Java type name to JNI type descriptor (mirrors Rust java_type_to_jni)
    function _jniType(t) {
        switch(t) {
            case "void": case "V": return "V";
            case "boolean": case "Z": return "Z";
            case "byte": case "B": return "B";
            case "char": case "C": return "C";
            case "short": case "S": return "S";
            case "int": case "I": return "I";
            case "long": case "J": return "J";
            case "float": case "F": return "F";
            case "double": case "D": return "D";
            default:
                if (t.charAt(0) === '[') return t.replace(/\./g, "/");
                return "L" + t.replace(/\./g, "/") + ";";
        }
    }

    // 获取方法列表（带缓存）
    function _getMethods(wrapper) {
        if (wrapper._cache && wrapper._cache.methods) return wrapper._cache.methods;
        var ms = _methods(wrapper._c);
        if (wrapper._cache) wrapper._cache.methods = ms;
        return ms;
    }

    // 根据参数签名前缀查找匹配的方法
    function _findOverload(ms, name, paramSig) {
        for (var i = 0; i < ms.length; i++) {
            if (ms[i].name === name && ms[i].sig.indexOf(paramSig) === 0) {
                return ms[i].sig;
            }
        }
        return null;
    }

    // Frida-compatible overload: accepts Java type names as arguments
    // e.g. .overload("java.lang.String", "int") → matches JNI sig "(Ljava/lang/String;I)..."
    // Also accepts raw JNI signature: .overload("(Ljava/lang/String;)I")
    // Also accepts arrays for multiple overloads: .overload(["int","int"], ["java.lang.String"])
    MethodWrapper.prototype.overload = function() {
        // Case 1: 数组语法，选择多个overload
        // .overload(["int", "int"], ["java.lang.String"])
        if (arguments.length >= 1 && Array.isArray(arguments[0])) {
            var ms = _getMethods(this);
            var name = this._m === "$init" ? "<init>" : this._m;
            var sigs = [];
            for (var a = 0; a < arguments.length; a++) {
                var params = arguments[a];
                var paramSig = "(";
                for (var i = 0; i < params.length; i++) {
                    paramSig += _jniType(params[i]);
                }
                paramSig += ")";
                var sig = _findOverload(ms, name, paramSig);
                if (!sig) {
                    throw new Error("No matching overload: " + this._c + "." + this._m + paramSig);
                }
                sigs.push(sig);
            }
            return new MethodWrapper(this._c, this._m, sigs, this._cache);
        }
        // Case 2: 原始JNI签名
        if (arguments.length === 1 && typeof arguments[0] === "string"
            && arguments[0].charAt(0) === '(') {
            return new MethodWrapper(this._c, this._m, arguments[0], this._cache);
        }
        // Case 3: Java类型名（现有行为）
        var paramSig = "(";
        for (var i = 0; i < arguments.length; i++) {
            paramSig += _jniType(arguments[i]);
        }
        paramSig += ")";
        var ms = _getMethods(this);
        var name = this._m === "$init" ? "<init>" : this._m;
        var sig = _findOverload(ms, name, paramSig);
        if (!sig) {
            throw new Error("No matching overload: " + this._c + "." + this._m + paramSig);
        }
        return new MethodWrapper(this._c, this._m, sig, this._cache);
    };

    Object.defineProperty(MethodWrapper.prototype, "impl", {
        get: function() { return this._fn || null; },
        set: function(fn) {
            var name = this._m === "$init" ? "<init>" : this._m;
            var cls = this._c;

            // 确定要hook的签名列表
            var sigs;
            if (this._s === null) {
                // 未指定overload：hook所有overload
                var ms = _getMethods(this);
                var match = [];
                for (var i = 0; i < ms.length; i++) {
                    if (ms[i].name === name) match.push(ms[i]);
                }
                if (match.length === 0)
                    throw new Error("Method not found: " + cls + "." + this._m);
                sigs = match.map(function(m) { return m.sig; });
            } else if (Array.isArray(this._s)) {
                // 通过数组语法指定的多个overload
                sigs = this._s;
            } else {
                // 单个overload
                sigs = [this._s];
            }

            if (fn === null || fn === undefined) {
                if (sigs.length > 1) _beginBatch();
                for (var i = 0; i < sigs.length; i++) {
                    _unhook(cls, name, sigs[i]);
                }
                if (sigs.length > 1) _endBatch();
                this._fn = null;
            } else {
                var userFn = fn;
                var wrapCallback = function(ctx) {
                    if (ctx.thisObj !== undefined) {
                        ctx.thisObj = _wrapJavaObj(ctx.thisObj, cls);
                    }
                    if (ctx.args) {
                        for (var i = 0; i < ctx.args.length; i++) {
                            var a = ctx.args[i];
                            if (a !== null && typeof a === "object"
                                && a.__jptr !== undefined) {
                                ctx.args[i] = _wrapJavaObj(a.__jptr, a.__jclass);
                            }
                        }
                    }
                    // Wrap callOriginal so returned objects auto-convert to JS Proxy
                    var origCallOriginal = ctx.callOriginal;
                    ctx.callOriginal = function() {
                        var ret = origCallOriginal.apply(null, arguments);
                        if (ret !== null && typeof ret === "object"
                            && ret.__jptr !== undefined) {
                            return _wrapJavaObj(ret.__jptr, ret.__jclass);
                        }
                        return ret;
                    };
                    return userFn(ctx);
                };
                for (var i = 0; i < sigs.length; i++) {
                    _hook(cls, name, sigs[i], wrapCallback);
                }
                this._fn = fn;
            }
        }
    });

    Java.use = function(cls) {
        var cache = {};
        var wrappers = {};
        return new Proxy({}, {
            get: function(_, prop) {
                if (typeof prop !== "string") return undefined;
                if (!wrappers[prop]) wrappers[prop] = new MethodWrapper(cls, prop, null, cache);
                return wrappers[prop];
            },
            ownKeys: function(_) {
                if (cache._ownKeys) return cache._ownKeys;
                var ms = _methods(cls);
                var seen = {};
                var keys = [];
                for (var i = 0; i < ms.length; i++) {
                    var n = ms[i].name === "<init>" ? "$init" : ms[i].name;
                    if (!seen[n]) { seen[n] = true; keys.push(n); }
                }
                cache._ownKeys = keys;
                return keys;
            },
            getOwnPropertyDescriptor: function(_, prop) {
                if (typeof prop !== "string") return undefined;
                return {enumerable: true, configurable: true};
            }
        });
    };

    // ========================================================================
    // Java.ready(fn) — 延迟到 app dex 加载后执行
    //
    // spawn 模式下脚本在 setArgV0 阶段加载，此时 app ClassLoader 还未创建，
    // FindClass 只能找到 framework 类。Java.ready() 通过 hook 框架类
    // Instrumentation.newApplication (ClassLoader 作为第一个参数传入) 来检测
    // dex 加载完成，在 Application.attachBaseContext 之前触发用户回调。
    //
    // 非 spawn 模式（attach 已运行的进程）时 ClassLoader 已就绪，立即执行。
    // ========================================================================
    var _readyCallbacks = [];
    var _readyFired = false;
    var _readyGateSig = "(Ljava/lang/ClassLoader;Ljava/lang/String;Landroid/content/Context;)Landroid/app/Application;";

    Java.ready = function(fn) {
        if (typeof fn !== "function") {
            throw new Error("Java.ready() requires a function argument");
        }

        // ClassLoader 已就绪（非 spawn / 已触发过），立即执行
        if (_readyFired || Java._isClassLoaderReady()) {
            _readyFired = true;
            fn();
            return;
        }

        // 首个注册：安装 gate hook
        if (_readyCallbacks.length === 0) {
            _hook("android/app/Instrumentation", "newApplication", _readyGateSig, function(ctx) {
                // 从第一个参数获取 ClassLoader 并更新缓存
                if (ctx.args && ctx.args[0] !== null && ctx.args[0] !== undefined) {
                    var clPtr = ctx.args[0];
                    if (typeof clPtr === "object" && clPtr.__jptr !== undefined) {
                        clPtr = clPtr.__jptr;
                    }
                    Java._updateClassLoader(clPtr);
                }

                // 执行所有排队的回调 — 用户可在此安装 hook
                // 注意：用户可能重新 hook newApplication，所以先保存 callOriginal 引用
                _readyFired = true;
                var cbs = _readyCallbacks;
                _readyCallbacks = [];
                for (var i = 0; i < cbs.length; i++) {
                    try {
                        cbs[i]();
                    } catch(e) {
                        console.log("[Java.ready] callback #" + i + " error: " + e);
                    }
                }

                // 调用原始方法 — app 继续 (attachBaseContext, onCreate 等)
                return ctx.callOriginal();
            });
        }

        _readyCallbacks.push(fn);
    };
})();
