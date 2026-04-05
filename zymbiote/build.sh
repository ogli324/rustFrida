#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 查找 NDK clang
# 优先使用 ANDROID_NDK_HOME 环境变量（CI 场景）
if [ -n "$ANDROID_NDK_HOME" ] && [ -d "$ANDROID_NDK_HOME" ]; then
    TOOLCHAIN_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
    if [ -f "$TOOLCHAIN_BIN/aarch64-linux-android33-clang" ]; then
        NDK_CC="$TOOLCHAIN_BIN/aarch64-linux-android33-clang"
    else
        NDK_CC=$(find -L "$ANDROID_NDK_HOME" -name "aarch64-linux-android*-clang" 2>/dev/null | grep -v '++' | sort -V | tail -1)
    fi
fi

# 回退：在 ~/Android/Sdk/ndk/ 中搜索（使用 -L 跟随符号链接）
if [ -z "$NDK_CC" ]; then
    NDK_BASE="$HOME/Android/Sdk/ndk"
    NDK_CC=$(find -L "$NDK_BASE" -name "aarch64-linux-android33-clang" 2>/dev/null | sort -V | tail -1)
fi

if [ -z "$NDK_CC" ]; then
    NDK_BASE="$HOME/Android/Sdk/ndk"
    # 尝试其他 API level
    NDK_CC=$(find -L "$NDK_BASE" -name "aarch64-linux-android*-clang" 2>/dev/null | grep -v '++' | sort -V | tail -1)
fi

if [ -z "$NDK_CC" ]; then
    echo "错误: 未找到 Android NDK clang，请确认 NDK 已安装在 ~/Android/Sdk/ndk/ 或设置 ANDROID_NDK_HOME 环境变量"
    exit 1
fi

echo "使用 NDK clang: $NDK_CC"

mkdir -p build

$NDK_CC -shared -nostdlib \
    -Wl,-T,helper.lds \
    -fvisibility=hidden \
    -fno-function-sections \
    -fno-data-sections \
    -fno-asynchronous-unwind-tables \
    -Os \
    -o build/zymbiote.elf \
    zymbiote.c

echo "编译完成: build/zymbiote.elf"
ls -la build/zymbiote.elf
