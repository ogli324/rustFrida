/// Return `$HOME/<suffix>` as a string.
fn dirs_or_home(suffix: &str) -> String {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/root".to_string());
    format!("{}/{}", home, suffix)
}

/// Find the latest NDK version directory under `ndk_base`.
fn find_latest_ndk(ndk_base: &str) -> Option<String> {
    let dir = std::fs::read_dir(ndk_base).ok()?;
    let mut versions: Vec<String> = dir
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    // Sort by numeric version components (e.g. "25.0.8775105" > "9.0.0")
    versions.sort_by(|a, b| {
        let parse = |s: &str| -> Vec<u64> {
            s.split('.').filter_map(|p| p.parse::<u64>().ok()).collect()
        };
        parse(a).cmp(&parse(b))
    });
    versions.last().map(|v| format!("{}/{}", ndk_base, v))
}

fn main() {
    cc::Build::new()
        .file("../agent/src/hide_soinfo.c")
        .compile("hide_soinfo");

    let manifest_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let workspace_root = manifest_dir
        .parent()
        .expect("qbdi-helper must live under the workspace root");
    let qbdi_archive = workspace_root.join("qbdi/libQBDI.a");

    println!("cargo:rustc-cdylib-link-arg={}", qbdi_archive.display());
    println!("cargo:rustc-link-lib=log");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_os == "android" && target_arch == "aarch64" {
        let ndk_path = std::env::var("NDK_PATH")
            .or_else(|_| std::env::var("ANDROID_NDK_HOME"))
            .unwrap_or_else(|_| {
                // Auto-detect: find latest NDK version under ~/Android/Sdk/ndk/
                let ndk_base = dirs_or_home("Android/Sdk/ndk");
                find_latest_ndk(&ndk_base)
                    .unwrap_or_else(|| panic!(
                        "Cannot find Android NDK. Set NDK_PATH or ANDROID_NDK_HOME, \
                         or install NDK under ~/Android/Sdk/ndk/"
                    ))
            });
        let cxx_lib_dir = std::path::PathBuf::from(&ndk_path)
            .join("toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android");
        let cxx_static = cxx_lib_dir.join("libc++_static.a");
        let cxxabi = cxx_lib_dir.join("libc++abi.a");

        println!("cargo:rustc-cdylib-link-arg={}", cxx_static.display());
        println!("cargo:rustc-cdylib-link-arg={}", cxxabi.display());
        println!("cargo:rustc-link-lib=dylib=c");
        println!("cargo:rustc-link-lib=dylib=dl");
        println!("cargo:rustc-link-lib=dylib=m");
    } else {
        println!("cargo:rustc-link-lib=c++");
    }

    println!(
        "cargo:rustc-cdylib-link-arg=-Wl,-u,get_hide_result,-u,rust_get_hide_result,--export-dynamic-symbol=get_hide_result,--export-dynamic-symbol=rust_get_hide_result"
    );
    println!("cargo:rerun-if-changed=../agent/src/hide_soinfo.c");
    println!("cargo:rerun-if-changed={}", qbdi_archive.display());
}
