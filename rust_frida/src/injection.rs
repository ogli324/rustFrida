#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use libc::{c_void, close, memfd_create, write as libc_write, MFD_CLOEXEC};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use std::ffi::CString;
use std::mem::size_of;
use std::os::unix::io::RawFd;

use crate::process::{
    attach_to_process, call_target_function, get_lib_base, write_bytes, write_memory,
};
use crate::types::{write_string_table, DlOffsets, LibcOffsets};
use crate::{log_error, log_info, log_success, log_verbose, log_verbose_addr, log_warn};

// 嵌入loader.bin
pub(crate) const SHELLCODE: &[u8] = include_bytes!("../../loader/build/loader.bin");

#[cfg(debug_assertions)]
pub(crate) const AGENT_SO: &[u8] =
    include_bytes!("../../target/aarch64-linux-android/debug/libagent.so");

#[cfg(not(debug_assertions))]
pub(crate) const AGENT_SO: &[u8] =
    include_bytes!("../../target/aarch64-linux-android/release/libagent.so");

pub(crate) fn create_memfd_with_data(name: &str, data: &[u8]) -> Result<RawFd, String> {
    let cname = CString::new(name).unwrap();
    let fd = unsafe { memfd_create(cname.as_ptr(), MFD_CLOEXEC) };
    if fd < 0 {
        return Err(format!(
            "memfd_create 失败: {}",
            std::io::Error::last_os_error()
        ));
    }
    // 写入数据
    let mut written = 0;
    while written < data.len() {
        let ret = unsafe {
            libc_write(
                fd,
                data[written..].as_ptr() as *const c_void,
                data.len() - written,
            )
        };
        if ret < 0 {
            unsafe { close(fd) };
            return Err(format!(
                "memfd 写入失败: {}",
                std::io::Error::last_os_error()
            ));
        }
        written += ret as usize;
    }
    Ok(fd)
}

/// 注入 agent 到目标进程
pub(crate) fn inject_to_process(
    pid: i32,
    string_overrides: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    log_info!("正在附加到进程 PID: {}", pid);

    // 获取自身和目标进程的 libc / libdl 基址
    let self_base = get_lib_base(None, "libc.so")?;
    let target_base = get_lib_base(Some(pid), "libc.so")?;
    let self_dl_base = get_lib_base(None, "libdl.so")?;
    let target_dl_base = get_lib_base(Some(pid), "libdl.so")?;

    log_verbose!("自身 libc.so 基址: 0x{:x}", self_base);
    log_verbose!("目标进程 libc.so 基址: 0x{:x}", target_base);
    log_verbose!("自身 libdl.so 基址: 0x{:x}", self_dl_base);
    log_verbose!("目标进程 libdl.so 基址: 0x{:x}", target_dl_base);

    // 计算目标进程中的函数地址
    let offsets = LibcOffsets::calculate(self_base, target_base)?;
    let dl_offsets = DlOffsets::calculate(self_dl_base, target_dl_base)?;

    // 打印所有函数地址（仅 verbose 模式）
    if crate::logger::is_verbose() {
        offsets.print_offsets();
        dl_offsets.print_offsets();
    }

    // 附加到目标进程
    attach_to_process(pid)?;
    log_verbose!("开始分配内存");

    // 分配内存用于shellcode
    let page_size = 4096;
    let shellcode_len = ((SHELLCODE.len() + page_size - 1) / page_size) * page_size;
    let mmap_prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
    let mmap_flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    let shellcode_addr = call_target_function(
        pid,
        offsets.mmap,
        &[
            0, // addr = NULL，让内核分配
            shellcode_len,
            mmap_prot as usize,
            mmap_flags as usize,
            !0usize, // fd = -1
            0,       // offset = 0
        ],
        None,
    )
    .map_err(|e| format!("调用 mmap 失败: {}", e))?;

    log_verbose!("分配shellcode内存");
    log_verbose_addr!("地址", shellcode_addr);

    // 写入shellcode
    write_bytes(pid, shellcode_addr, SHELLCODE)?;
    log_verbose!("Shellcode写入成功");
    log_verbose_addr!("地址", shellcode_addr);

    // 分配内存用于LibcOffsets结构体
    let offsets_size = size_of::<LibcOffsets>();
    let offsets_addr = call_target_function(pid, offsets.malloc, &[offsets_size], None)
        .map_err(|e| format!("分配offsets内存失败: {}", e))?;

    log_verbose!("分配offsets内存");
    log_verbose_addr!("地址", offsets_addr);

    // 写入LibcOffsets结构体
    write_memory(pid, offsets_addr, &offsets)?;
    log_verbose!("Offsets写入成功");
    log_verbose_addr!("地址", offsets_addr);

    let dloffset_size = size_of::<DlOffsets>();
    let dloffset_addr = call_target_function(pid, offsets.malloc, &[dloffset_size], None)
        .map_err(|e| format!("分配dloffsets内存失败: {}", e))?;

    log_verbose!("分配dloffsets内存");
    log_verbose_addr!("地址", dloffset_addr);

    // 写入DlOffsets结构体
    write_memory(pid, dloffset_addr, &dl_offsets)?;
    log_verbose!("DlOffsets写入成功");
    log_verbose_addr!("地址", dloffset_addr);

    // 写入字符串表
    let string_table_addr = write_string_table(pid, offsets.malloc, string_overrides)?;
    log_verbose!("字符串表写入成功");
    log_verbose_addr!("地址", string_table_addr);

    // 使用 call_target_function 调用 shellcode
    match call_target_function(
        pid,
        shellcode_addr,
        &[offsets_addr, dloffset_addr, string_table_addr],
        None,
    ) {
        Ok(return_value) => {
            log_verbose!("Shellcode 执行完成，返回值: 0x{:x}", return_value as isize);

            // 释放shellcode内存
            log_verbose!("正在释放shellcode内存...");
            match call_target_function(pid, offsets.munmap, &[shellcode_addr, shellcode_len], None)
            {
                Ok(_) => log_verbose!("Shellcode内存释放成功"),
                Err(e) => log_error!("释放shellcode内存失败: {}", e),
            }

            // detach 目标进程
            if let Err(e) = ptrace::detach(Pid::from_raw(pid), None) {
                log_error!("分离目标进程失败: {}", e);
            } else {
                log_success!("已分离目标进程");
            }
            Ok(())
        }
        Err(e) => {
            log_error!("执行 shellcode 失败: {}", e);
            log_warn!("暂停目标进程，等待调试器附加...");
            // 发送 SIGSTOP 让目标进程暂停
            let _ = ptrace::cont(Pid::from_raw(pid), Some(Signal::SIGSTOP));
            Err(e)
        }
    }
}

/// 根据 UID 查找 /data/data/ 目录下对应的应用数据目录
fn find_data_dir_by_uid(uid: u32) -> Option<String> {
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    let data_dir = "/data/data";

    match fs::read_dir(data_dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.uid() == uid {
                        if let Some(path) = entry.path().to_str() {
                            return Some(path.to_string());
                        }
                    }
                }
            }
            None
        }
        Err(e) => {
            log_error!("读取 /data/data 目录失败: {}", e);
            None
        }
    }
}

/// 使用 eBPF 监听 SO 加载并自动附加
pub(crate) fn watch_and_inject(
    so_pattern: &str,
    timeout_secs: Option<u64>,
    string_overrides: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    use ldmonitor::DlopenMonitor;
    use std::time::Duration;

    log_info!("正在启动 eBPF 监听器，等待加载: {}", so_pattern);

    let monitor = DlopenMonitor::new(None).map_err(|e| format!("启动 eBPF 监听失败: {}", e))?;

    let info = if let Some(secs) = timeout_secs {
        log_info!("超时时间: {} 秒", secs);
        monitor.wait_for_path_timeout(so_pattern, Duration::from_secs(secs))
    } else {
        log_info!("无超时限制，持续监听中...");
        monitor.wait_for_path(so_pattern)
    };

    monitor.stop();

    match info {
        Some(dlopen_info) => {
            let pid = dlopen_info.pid();
            if let Some(ns_pid) = dlopen_info.ns_pid {
                if ns_pid != dlopen_info.host_pid {
                    log_success!(
                        "检测到 SO 加载: pid={} (host_pid={}), uid={}, path={}",
                        ns_pid,
                        dlopen_info.host_pid,
                        dlopen_info.uid,
                        dlopen_info.path
                    );
                } else {
                    log_success!(
                        "检测到 SO 加载: pid={}, uid={}, path={}",
                        pid,
                        dlopen_info.uid,
                        dlopen_info.path
                    );
                }
            } else {
                log_success!(
                    "检测到 SO 加载: host_pid={}, uid={}, path={}",
                    dlopen_info.host_pid,
                    dlopen_info.uid,
                    dlopen_info.path
                );
            }

            // 克隆 string_overrides 以便修改
            let mut overrides = string_overrides.clone();

            // 根据 uid 自动检测 /data/data/ 目录
            if let Some(data_dir) = find_data_dir_by_uid(dlopen_info.uid) {
                log_info!("自动检测到应用数据目录: {}", data_dir);
                overrides.insert("output_path".to_string(), data_dir);
            } else {
                log_warn!("未能找到 uid {} 对应的 /data/data/ 目录", dlopen_info.uid);
            }

            inject_to_process(pid as i32, &overrides)
        }
        None => Err("监听超时，未检测到匹配的 SO 加载".to_string()),
    }
}
