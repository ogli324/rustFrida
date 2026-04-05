#!/usr/bin/env python3
"""
configure.py — Auto-detect Android NDK and generate .cargo/config.toml.

Usage:
    python3 configure.py                          # auto-detect NDK
    python3 configure.py --ndk /path/to/ndk       # explicit NDK path
    ANDROID_NDK_HOME=/path/to/ndk python3 configure.py  # via env var

NDK search order:
  1. --ndk command-line argument
  2. ANDROID_NDK_HOME environment variable
  3. NDK_PATH environment variable
  4. ~/Android/Sdk/ndk/<latest version>
"""

import argparse
import glob
import os
import platform
import sys


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CARGO_CONFIG = os.path.join(SCRIPT_DIR, ".cargo", "config.toml")
API_LEVEL = 33


def _version_key(name):
    """Parse a version directory name like '25.0.8775105' into a comparable tuple."""
    parts = []
    for p in name.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return parts


def find_ndk(explicit_path=None):
    """Find the Android NDK, checking multiple locations."""
    # 1. Explicit argument
    if explicit_path:
        if os.path.isdir(explicit_path):
            return os.path.abspath(explicit_path)
        print(f"错误: 指定的 NDK 路径不存在: {explicit_path}")
        sys.exit(1)

    # 2. Environment variables
    for var in ("ANDROID_NDK_HOME", "NDK_PATH"):
        val = os.environ.get(var)
        if val and os.path.isdir(val):
            return os.path.abspath(val)

    # 3. Default SDK location
    ndk_base = os.path.expanduser("~/Android/Sdk/ndk")
    if os.path.isdir(ndk_base):
        versions = sorted(os.listdir(ndk_base), key=_version_key, reverse=True)
        for v in versions:
            candidate = os.path.join(ndk_base, v)
            if os.path.isdir(candidate):
                return candidate

    return None


def detect_host_tag():
    """Detect the NDK host platform tag (e.g. linux-x86_64, darwin-x86_64)."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "linux":
        return "linux-x86_64"
    elif system == "darwin":
        # NDK r23+ ships native arm64 builds; prefer them on Apple Silicon
        if machine == "arm64":
            return "darwin-arm64"
        return "darwin-x86_64"
    elif system == "windows":
        return "windows-x86_64"
    else:
        return f"{system}-{machine}"


def find_clang_rt_dir(toolchain_dir):
    """Find the clang_rt builtins directory (baremetal) under the toolchain."""
    # Pattern: lib/clang/<version>/lib/baremetal  OR  lib64/clang/<version>/lib/baremetal
    for lib_dir_name in ("lib64", "lib"):
        base = os.path.join(toolchain_dir, lib_dir_name, "clang")
        if not os.path.isdir(base):
            continue
        versions = sorted(os.listdir(base), reverse=True)
        for ver in versions:
            baremetal = os.path.join(base, ver, "lib", "baremetal")
            if os.path.isdir(baremetal):
                return baremetal
    # Try newer NDK layout: lib/clang/<version>/lib/linux/
    for lib_dir_name in ("lib64", "lib"):
        base = os.path.join(toolchain_dir, lib_dir_name, "clang")
        if not os.path.isdir(base):
            continue
        versions = sorted(os.listdir(base), reverse=True)
        for ver in versions:
            linux_dir = os.path.join(base, ver, "lib", "linux")
            if os.path.isdir(linux_dir):
                return linux_dir
    return None


def validate_ndk(ndk_path, host_tag):
    """Validate that the NDK path has the expected toolchain structure."""
    toolchain_dir = os.path.join(ndk_path, "toolchains", "llvm", "prebuilt", host_tag)
    bin_dir = os.path.join(toolchain_dir, "bin")
    sysroot = os.path.join(toolchain_dir, "sysroot")

    errors = []
    if not os.path.isdir(toolchain_dir):
        errors.append(f"  工具链目录不存在: {toolchain_dir}")
    if not os.path.isdir(bin_dir):
        errors.append(f"  bin 目录不存在: {bin_dir}")
    if not os.path.isdir(sysroot):
        errors.append(f"  sysroot 不存在: {sysroot}")

    # Check for clang
    clang_name = f"aarch64-linux-android{API_LEVEL}-clang"
    ext = ".cmd" if host_tag.startswith("windows") else ""
    clang = os.path.join(bin_dir, clang_name + ext)
    if not os.path.isfile(clang):
        # Fallback names
        fallbacks = [
            os.path.join(bin_dir, "aarch64-linux-android-clang" + ext),
            os.path.join(bin_dir, "clang" + ext),
        ]
        found = False
        for fb in fallbacks:
            if os.path.isfile(fb):
                found = True
                break
        if not found:
            errors.append(f"  clang 不存在: {clang}")

    return errors


def generate_config(ndk_path, host_tag):
    """Generate .cargo/config.toml content."""
    toolchain_dir = os.path.join(ndk_path, "toolchains", "llvm", "prebuilt", host_tag)
    bin_dir = os.path.join(toolchain_dir, "bin")
    sysroot = os.path.join(toolchain_dir, "sysroot")

    ext = ".cmd" if host_tag.startswith("windows") else ""

    # Find clang
    clang = os.path.join(bin_dir, f"aarch64-linux-android{API_LEVEL}-clang{ext}")
    if not os.path.isfile(clang):
        clang = os.path.join(bin_dir, f"aarch64-linux-android-clang{ext}")
    if not os.path.isfile(clang):
        clang = os.path.join(bin_dir, f"clang{ext}")

    # Find ar
    ar_ext = ".exe" if host_tag.startswith("windows") else ""
    ar = os.path.join(bin_dir, f"llvm-ar{ar_ext}")

    # Find clang_rt builtins directory
    clang_rt_dir = find_clang_rt_dir(toolchain_dir)

    lines = [
        "## Auto-generated by configure.py — re-run to update.",
        f"## NDK: {ndk_path}",
        f"## Host: {host_tag}",
        "",
        "[build]",
        'target = "aarch64-linux-android"',
        "",
        "[target.aarch64-linux-android]",
        f'linker = "{clang}"',
        f'ar = "{ar}"',
    ]

    if clang_rt_dir:
        lines.append(
            f'rustflags = ["-l","clang_rt.builtins-aarch64","-L","{clang_rt_dir}"]'
        )
    else:
        lines.append("# 警告: 未找到 clang_rt builtins 目录，可能需要手动设置 rustflags")
        lines.append('# rustflags = ["-l","clang_rt.builtins-aarch64","-L","<path>"]')

    lines += [
        "",
        "[env]",
        f'CC_aarch64-linux-android = "{clang}"',
        f'BINDGEN_EXTRA_CLANG_ARGS = "--sysroot={sysroot}"',
    ]

    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Auto-detect Android NDK and generate .cargo/config.toml"
    )
    parser.add_argument(
        "--ndk",
        help="Explicit path to Android NDK root (overrides env vars and auto-detection)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print generated config without writing",
    )
    args = parser.parse_args()

    print("=== rustFrida configure ===\n")

    # Find NDK
    ndk = find_ndk(args.ndk)
    if not ndk:
        print("错误: 找不到 Android NDK。请通过以下方式之一指定：")
        print("  1. python3 configure.py --ndk /path/to/ndk")
        print("  2. export ANDROID_NDK_HOME=/path/to/ndk")
        print("  3. 安装 NDK 到 ~/Android/Sdk/ndk/")
        sys.exit(1)

    host_tag = detect_host_tag()
    print(f"NDK 路径:  {ndk}")
    print(f"主机平台:  {host_tag}")
    print(f"API Level: {API_LEVEL}")

    # Validate
    errors = validate_ndk(ndk, host_tag)
    if errors:
        print("\n警告: NDK 验证发现以下问题:")
        for e in errors:
            print(e)
        print("\n生成的配置可能不完整，请检查。\n")

    # Generate
    config_content = generate_config(ndk, host_tag)

    if args.dry_run:
        print("\n--- 生成的 .cargo/config.toml (dry-run) ---")
        print(config_content)
        return

    # Write
    os.makedirs(os.path.dirname(CARGO_CONFIG), exist_ok=True)
    with open(CARGO_CONFIG, "w") as f:
        f.write(config_content)

    print(f"\n✓ 已生成: {CARGO_CONFIG}")
    print("\n后续步骤:")
    print("  1. python3 loader/build_helpers.py       # 构建 loader shellcode")
    print("  2. cargo build -p agent --release        # 构建 agent SO")
    print("  3. cargo build -p rust_frida --release   # 构建 rustfrida 主程序")


if __name__ == "__main__":
    main()
