// Java.use() API — Frida-compatible syntax for Java method hooking
// Evaluated at engine init after C-level Java.hook/unhook/_methods/_getFieldAuto are registered.
(function() {
    "use strict";
    var _hook = Java.hook;
    var _unhook = Java.unhook;
    var _methods = Java._methods;
    var _getFieldAuto = Java._getFieldAuto;
    delete Java.hook;
    delete Java.unhook;
    delete Java._methods;
    delete Java._getFieldAuto;

    // Wrap a raw Java object pointer as a Proxy for field access via dot notation.
    // e.g. ctx.thisObj.mTitle reads the mTitle field via JNI reflection.
    function _wrapJavaObj(ptr, cls) {
        return new Proxy({__jptr: ptr, __jclass: cls}, {
            get: function(target, prop) {
                if (prop === "__jptr") return target.__jptr;
                if (prop === "__jclass") return target.__jclass;
                if (typeof prop !== "string") return undefined;
                if (prop === "toString") return function() {
                    return "[JavaObject:" + target.__jclass + "]";
                };
                if (prop === "valueOf") return function() {
                    return "[JavaObject:" + target.__jclass + "]";
                };
                var result = _getFieldAuto(target.__jptr, target.__jclass, prop);
                // Object fields come back as {__jptr, __jclass} — wrap recursively
                if (result !== null && typeof result === "object"
                    && result.__jptr !== undefined) {
                    return _wrapJavaObj(result.__jptr, result.__jclass);
                }
                return result;
            }
        });
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
                for (var i = 0; i < sigs.length; i++) {
                    _unhook(cls, name, sigs[i]);
                }
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
})();
