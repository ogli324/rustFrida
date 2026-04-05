# rustFrida

ARM64 Android 动态插桩框架。

## 环境要求

- Android NDK 25+（默认路径 `~/Android/Sdk/ndk/`）
- Rust toolchain + `aarch64-linux-android` target
- Python 3（构建 loader shellcode + 配置脚本）

## 首次配置

运行 `configure.py` 自动检测 NDK 并生成 `.cargo/config.toml`：

```bash
# 自动检测 NDK（默认搜索 ~/Android/Sdk/ndk/）
python3 configure.py

# 或指定 NDK 路径
python3 configure.py --ndk /path/to/ndk

# 或通过环境变量
export ANDROID_NDK_HOME=/path/to/ndk
python3 configure.py
```

确保已安装 Rust aarch64-linux-android target：
```bash
rustup target add aarch64-linux-android
```

## 构建

最终产物 `rustfrida` 通过 `include_bytes!` 内嵌了 loader shellcode 和 agent SO，有严格的**构建顺序**：

```
loader shellcode  ──┐
                    ├──→  rustfrida (主程序)
agent (libagent.so) ┘
```

### 1. 构建 loader shellcode（bootstrapper + rustfrida-loader）

```bash
python3 build_helpers.py
# 输出:
#   loader/build/bootstrapper.bin
#   loader/build/rustfrida-loader.bin
```

loader 是 bare-metal ARM64 shellcode，被 `rustfrida` 通过 `include_bytes!` 嵌入。**修改 loader C 代码后需重新运行此步。**

### 2. 构建 agent（libagent.so）

```bash
cargo build -p agent --release
# 输出: target/aarch64-linux-android/release/libagent.so
```

agent 是注入到目标进程的动态库，包含 hook 引擎、QuickJS、Java hook 等。**必须先于 rustfrida 构建**，因为 rustfrida 通过 `include_bytes!` 嵌入 agent SO。

### 3. 构建 rustfrida（主程序）

```bash
cargo build -p rust_frida --release
# 输出: target/aarch64-linux-android/release/rustfrida
```

rustfrida 内嵌了 `bootstrapper.bin` + `rustfrida-loader.bin` + `libagent.so`，是一个自包含的单文件。

### 可选组件（单独构建）

这些不在 default-members 里，按需构建：

**QBDI Trace 支持：** 需要先构建 qbdi-helper SO，再用 `--features qbdi` 编译 agent 和 rustfrida：

```bash
cargo build -p qbdi-helper --release           # → libqbdi_helper.so
cargo build -p agent --release --features qbdi  # agent 启用 qbdi feature
cargo build -p rust_frida --release --features qbdi  # rustfrida 嵌入 qbdi-helper SO
```

**eBPF SO 加载监控（`--watch-so`）：** ldmonitor 是 rustfrida 的编译依赖，默认构建已包含，`--watch-so` 无需额外步骤。如需独立使用 ldmonitor 命令行工具：

```bash
cargo build -p ldmonitor --release    # → ldmonitor 独立二进制
```

## 部署 & 运行

```bash
adb push target/aarch64-linux-android/release/rustfrida /data/local/tmp/

# PID 注入
./rustfrida --pid <pid>
./rustfrida --pid <pid> -l script.js

# Spawn 模式（启动时注入）
./rustfrida --spawn com.example.app
./rustfrida --spawn com.example.app -l script.js

# 等待 SO 加载后注入（eBPF）
./rustfrida --watch-so libnative.so

# 详细日志
./rustfrida --pid <pid> --verbose
```

### REPL 命令

```
jsinit              # 初始化 JS 引擎
jseval <expr>       # 求值表达式
loadjs <script>     # 执行脚本
jsrepl              # 交互式 REPL（Tab 补全）
exit                # 退出
```

---

## JS API 参考

### 全局对象一览

`console`, `ptr()`, `Memory`, `Module`, `hook()`, `unhook()`, `callNative()`, `qbdi`, `Java`, `Jni`

### 常用类型别名

| 类型名 | 实际含义 |
| --- | --- |
| `AddressLike` | `NativePointer \| number \| bigint \| "0x..."` |
| `NativePointer` | `ptr()` 创建的指针对象 |
| `JavaObjectProxy` | `Java.use()` / Java hook 中返回的 Java 对象代理 |

### 结构体 / 上下文对象

```ts
type ModuleInfo = {
  name: string; base: NativePointer; size: number; path: string
}

type NativeHookContext = {
  x0 ~ x30: number | bigint    // ARM64 通用寄存器
  sp: number | bigint
  pc: number | bigint
  trampoline: number | bigint
  orig(): number | bigint       // 调用原函数，返回值写入 x0
}

type JavaHookContext = {
  thisObj?: JavaObjectProxy     // 实例方法的 this（静态方法无）
  args: any[]                   // 参数数组
  env: number | bigint          // JNIEnv*
  orig(...args: any[]): any     // 调原方法，不传参用原始参数
}

type JniEntry = { name: string; index: number; address: NativePointer }

type JNINativeMethodInfo = {
  address: NativePointer; namePtr: NativePointer; sigPtr: NativePointer
  fnPtr: NativePointer; name: string | null; sig: string | null
}
```

---

## Native Hook

```js
// 基本 hook — 透传
hook(Module.findExportByName("libc.so", "open"), function(ctx) {
    console.log("open:", Memory.readCString(ptr(ctx.x0)));
    return ctx.orig();
});

// 修改返回值
hook(Module.findExportByName("libc.so", "getpid"), function(ctx) {
    ctx.orig();
    return 12345;              // 调用方拿到 12345
});

// 修改参数 — 通过 ctx 属性
hook(target, function(ctx) {
    ctx.x0 = ptr("0x1234");   // 改第一个参数
    ctx.x1 = 100;             // 改第二个参数
    return ctx.orig();         // 用修改后的参数调原函数
});

// 修改参数 — 通过 orig() 传参（按顺序覆盖 x0-xN）
hook(target, function(ctx) {
    return ctx.orig(ptr("0x1234"), 100);
});

// 不 return 也行 — ctx.x0 赋值会同步回 C 层
hook(Module.findExportByName("libc.so", "getuid"), function(ctx) {
    ctx.orig();
    ctx.x0 = 77777;           // 调用方拿到 77777
});

// 移除 hook
unhook(Module.findExportByName("libc.so", "open"));

// 直接调用 native 函数（最多 6 个参数，走 x0-x5）
var pid = callNative(Module.findExportByName("libc.so", "getpid"));
```

### Stealth 模式

```js
hook(target, callback, Hook.NORMAL)     // 0: mprotect 直写（默认）
hook(target, callback, Hook.WXSHADOW)   // 1: 内核 shadow 页，/proc/mem 不可见
hook(target, callback, Hook.RECOMP)     // 2: 代码页重编译，仅 4B patch
hook(target, callback, 1)               // 数字也行
hook(target, callback, true)            // true = WXSHADOW
```

### API 速查

| API | 参数 | 返回 |
| --- | --- | --- |
| `hook(target, callback, stealth?)` | `AddressLike, Function, number?` | `boolean` |
| `unhook(target)` | `AddressLike` | `boolean` |
| `callNative(func, ...args)` | `AddressLike, ...AddressLike` (最多6个) | `number \| bigint` |
| `diagAllocNear(addr)` | `AddressLike` | `undefined` |

---

## Java Hook

```js
Java.ready(function() {
    var Activity = Java.use("android.app.Activity");

    // hook 实例方法（return 值就是方法返回值）
    Activity.onResume.impl = function(ctx) {
        console.log("onResume:", ctx.thisObj.$className);
        return ctx.orig();
    };

    // hook 构造函数
    var MyClass = Java.use("com.example.MyClass");
    MyClass.$init.impl = function(ctx) {
        console.log("new MyClass, arg0 =", ctx.args[0]);
        return ctx.orig();
    };

    // 修改参数
    MyClass.test.impl = function(ctx) {
        return ctx.orig("patched_arg");
    };

    // 指定 overload（Java 类型名或 JNI 签名都行）
    MyClass.foo.overload("int", "java.lang.String").impl = function(ctx) {
        return ctx.orig();
    };

    // 移除 hook
    Activity.onResume.impl = null;
});
```

### Java.use 对象操作

```js
var JString = Java.use("java.lang.String");
var s = JString.$new("hello");     // 创建对象
console.log(s.length());           // 调实例方法
console.log(s.$className);         // 类名

var Process = Java.use("android.os.Process");
console.log(Process.myPid());      // 调静态方法
```

### Java.ready

Spawn 模式下 app ClassLoader 未就绪，用 `Java.ready` 延迟执行。PID 注入模式下立即执行。

### Stealth 模式（Java hook）

```js
Java.setStealth(0);  // Normal: mprotect 直写
Java.setStealth(1);  // WxShadow: shadow 页，CRC 校验不可见
Java.setStealth(2);  // Recomp: 代码页重编译
Java.getStealth();   // 查询当前模式 (0/1/2)
```

须在 `Java.use().impl` 之前设置。

### Deopt API

```js
Java.deopt();                  // 清空 JIT 缓存（InvalidateAllMethods）
Java.deoptimizeBootImage();    // boot image AOT 降级为 interpreter (API >= 26)
Java.deoptimizeEverything();   // 全局强制解释执行
Java.deoptimizeMethod("com.example.Test", "foo", "(I)V");  // 单方法降级
```

手动调用的工具函数，hook 流程不自动使用。

### API 速查

| API | 参数 | 返回 |
| --- | --- | --- |
| `Java.use(className)` | `string` | `JavaClassWrapper` |
| `Class.$new(...args)` | 任意 | `JavaObjectProxy` |
| `Class.method.impl = fn` | `(ctx: JavaHookContext) => any` | setter |
| `Class.method.impl = null` | — | setter |
| `Class.method.overload(...types)` | `string...` | `MethodWrapper` |
| `Java.ready(fn)` | `() => void` | `void` |
| `Java.deopt()` | — | `boolean` |
| `Java.deoptimizeBootImage()` | — | `boolean` |
| `Java.deoptimizeEverything()` | — | `boolean` |
| `Java.deoptimizeMethod(cls, method, sig)` | `string, string, string` | `boolean` |
| `Java.setStealth(mode)` | `number (0/1/2)` | — |
| `Java.getStealth()` | — | `number` |
| `Java.getField(objPtr, cls, field, sig)` | `AddressLike, string, string, string` | `any` |

---

## JNI API

```js
Jni.addr("RegisterNatives")       // → NativePointer
Jni.FindClass                     // 属性直接取地址
Jni.find("FindClass")             // → { name, index, address }
Jni.table                         // 整张 JNI 函数表
Jni.addr(envPtr, "FindClass")     // 指定 JNIEnv
```

### Jni.helper

```js
Jni.helper.env.ptr                         // 当前线程 JNIEnv*
Jni.helper.env.getClassName(jclass)        // → "android.app.Activity"
Jni.helper.env.getObjectClassName(jobject)  // → 对象的类名
Jni.helper.env.readJString(jstring)        // → JS string
Jni.helper.env.getObjectClass(obj)         // → jclass
Jni.helper.env.getSuperclass(clazz)        // → jclass
Jni.helper.env.isSameObject(a, b)          // → boolean
Jni.helper.env.isInstanceOf(obj, clazz)    // → boolean
Jni.helper.env.exceptionCheck()            // → boolean
Jni.helper.env.exceptionClear()

Jni.helper.structs.JNINativeMethod.readArray(addr, count)  // → JNINativeMethodInfo[]
Jni.helper.structs.jvalue.readArray(addr, typesOrSig)      // → any[]
```

### API 速查

| API | 参数 | 返回 |
| --- | --- | --- |
| `Jni.addr(name)` | `string` | `NativePointer` |
| `Jni.addr(env, name)` | `AddressLike, string` | `NativePointer` |
| `Jni.find(name)` | `string` | `JniEntry` |
| `Jni.entries()` | — | `JniEntry[]` |
| `Jni.table` | — | `Record<string, JniEntry>` |
| `Jni.helper.env.getClassName(clazz)` | `AddressLike` | `string \| null` |
| `Jni.helper.env.readJString(jstr)` | `AddressLike` | `string \| null` |
| `Jni.helper.structs.JNINativeMethod.readArray(addr, count)` | `AddressLike, number` | `JNINativeMethodInfo[]` |

### 实战：监控 RegisterNatives

```js
hook(Jni.addr("RegisterNatives"), function(ctx) {
    var cls = Jni.helper.env.getClassName(ctx.x1);
    var count = Number(ctx.x3);
    console.log(cls + " (" + count + " methods)");

    var methods = Jni.helper.structs.JNINativeMethod.readArray(ptr(ctx.x2), count);
    for (var i = 0; i < methods.length; i++) {
        var m = methods[i];
        var mod = Module.findByAddress(m.fnPtr);
        console.log("  " + m.name + " " + m.sig + " → " + mod.name + "+" + m.fnPtr.sub(mod.base));
    }
    return ctx.orig();
}, 1);
```

---

## Memory

| API | 参数 | 返回 |
| --- | --- | --- |
| `Memory.readU8(addr)` | `AddressLike` | `number` |
| `Memory.readU16(addr)` | `AddressLike` | `number` |
| `Memory.readU32(addr)` | `AddressLike` | `bigint` |
| `Memory.readU64(addr)` | `AddressLike` | `bigint` |
| `Memory.readPointer(addr)` | `AddressLike` | `NativePointer` |
| `Memory.readCString(addr)` | `AddressLike` | `string` (最多 4096B) |
| `Memory.readUtf8String(addr)` | `AddressLike` | `string` |
| `Memory.readByteArray(addr, len)` | `AddressLike, number` | `ArrayBuffer` |
| `Memory.writeU8(addr, value)` | `AddressLike, number` | `undefined` |
| `Memory.writeU16(addr, value)` | `AddressLike, number` | `undefined` |
| `Memory.writeU32(addr, value)` | `AddressLike, number` | `undefined` |
| `Memory.writeU64(addr, value)` | `AddressLike, bigint` | `undefined` |
| `Memory.writePointer(addr, value)` | `AddressLike, AddressLike` | `undefined` |

无效地址抛 `RangeError`，不会崩进程。

## Module

| API | 参数 | 返回 |
| --- | --- | --- |
| `Module.findExportByName(module, symbol)` | `string, string` | `NativePointer \| null` |
| `Module.findBaseAddress(module)` | `string` | `NativePointer \| null` |
| `Module.findByAddress(addr)` | `AddressLike` | `ModuleInfo \| null` |
| `Module.enumerateModules()` | — | `ModuleInfo[]` |

## ptr / NativePointer

```js
var p = ptr("0x7f12345678");   // hex string / number / BigInt / NativePointer
p.add(0x100)                   // → NativePointer
p.sub(offset)                  // → NativePointer
p.toString()                   // → "0x7f12345678"
```

| API | 参数 | 返回 |
| --- | --- | --- |
| `ptr(value)` | `number \| bigint \| string \| NativePointer` | `NativePointer` |
| `p.add(offset)` | `AddressLike` | `NativePointer` |
| `p.sub(offset)` | `AddressLike` | `NativePointer` |
| `p.toString()` | — | `string` |
| `p.toNumber()` | — | `bigint` |

## console

`console.log(...)` / `console.info(...)` / `console.warn(...)` / `console.error(...)` / `console.debug(...)`

## QBDI Trace

| API | 参数 | 返回 |
| --- | --- | --- |
| `qbdi.newVM()` | — | `number` |
| `qbdi.destroyVM(vm)` | `number` | `boolean` |
| `qbdi.addInstrumentedModuleFromAddr(vm, addr)` | `number, AddressLike` | `boolean` |
| `qbdi.addInstrumentedRange(vm, start, end)` | `number, AddressLike, AddressLike` | `boolean` |
| `qbdi.removeInstrumentedRange(vm, start, end)` | `number, AddressLike, AddressLike` | `boolean` |
| `qbdi.removeAllInstrumentedRanges(vm)` | `number` | `boolean` |
| `qbdi.allocateVirtualStack(vm, size)` | `number, number` | `boolean` |
| `qbdi.simulateCall(vm, retAddr, ...args)` | `number, AddressLike, ...AddressLike` | `boolean` |
| `qbdi.call(vm, target, ...args)` | `number, AddressLike, ...AddressLike` | `NativePointer \| null` |
| `qbdi.run(vm, start, stop)` | `number, AddressLike, AddressLike` | `boolean` |
| `qbdi.getGPR(vm, reg)` | `number, number` | `NativePointer` |
| `qbdi.setGPR(vm, reg, value)` | `number, number, AddressLike` | `boolean` |
| `qbdi.registerTraceCallbacks(vm, target, outDir?)` | `number, AddressLike, string?` | `boolean` |
| `qbdi.unregisterTraceCallbacks(vm)` | `number` | `boolean` |
| `qbdi.lastError()` | — | `string` |

常用寄存器常量：`qbdi.REG_RETURN`, `qbdi.REG_SP`, `qbdi.REG_LR`, `qbdi.REG_PC`

```js
var vm = qbdi.newVM();
qbdi.addInstrumentedModuleFromAddr(vm, target);
qbdi.allocateVirtualStack(vm, 0x100000);
qbdi.simulateCall(vm, 0, arg0, arg1);
qbdi.registerTraceCallbacks(vm, target);
qbdi.run(vm, target, 0);
var ret = qbdi.getGPR(vm, qbdi.REG_RETURN);
qbdi.unregisterTraceCallbacks(vm);
qbdi.destroyVM(vm);
```

Trace 文件默认输出到 `/data/data/<package>/trace_bundle.pb`，配合 qbdi-replay + IDA 插件回放。

---

## 注意事项

- **两种 hook 都建议 `return ctx.orig()`** 透传返回值
- **Native hook 改参数/返回值：** `ctx.x0 = value` 或 `ctx.orig(newArg0, newArg1)`，`return value` 覆盖返回值
- **Java hook 改参数/返回值：** `return ctx.orig(newArgs)` 改参数，`return value` 改返回值
- Spawn 模式下 Java hook 必须放在 `Java.ready(fn)` 里
- `Java.setStealth()` 必须在 `Java.use().impl` 之前调用
- `callNative()` 仅支持整数/指针参数（最多 6 个）

---

## 免责声明

本项目仅供安全研究、逆向工程学习和授权测试用途。使用者应确保在合法授权范围内使用本工具，遵守所在地区的法律法规。作者不对任何滥用、非法使用或由此造成的损失承担责任。使用本项目即表示您同意自行承担所有风险。
