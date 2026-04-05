#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 查找 NDK clang（优先环境变量，其次默认 SDK 目录）
NDK_CC=""
NDK_BASE="$HOME/Android/Sdk/ndk"
if [ -n "$ANDROID_NDK_HOME" ] && [ -d "$ANDROID_NDK_HOME" ]; then
    NDK_CC=$(find -L "$ANDROID_NDK_HOME" -name "aarch64-linux-android33-clang" 2>/dev/null | sort -V | tail -1)
    if [ -z "$NDK_CC" ]; then
        NDK_CC=$(find -L "$ANDROID_NDK_HOME" -name "aarch64-linux-android*-clang" 2>/dev/null | grep -v '++' | sort -V | tail -1)
    fi
fi

if [ -z "$NDK_CC" ]; then
    NDK_CC=$(find -L "$NDK_BASE" -name "aarch64-linux-android33-clang" 2>/dev/null | sort -V | tail -1)
fi

if [ -z "$NDK_CC" ]; then
    # 尝试其他 API level
    NDK_CC=$(find -L "$NDK_BASE" -name "aarch64-linux-android*-clang" 2>/dev/null | grep -v '++' | sort -V | tail -1)
fi

if [ -z "$NDK_CC" ]; then
    echo "错误: 未找到 Android NDK clang，请确认 NDK 已安装在 ~/Android/Sdk/ndk/"
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
