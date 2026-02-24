#![cfg(all(target_os = "android", target_arch = "aarch64"))]

mod args;
mod communication;
mod injection;
mod logger;
mod process;
mod repl;
mod types;

use args::Args;
use clap::Parser;
use communication::{
    check_agent_running, eval_state, start_socket_listener, AGENT_DISCONNECTED, AGENT_MEMFD,
    AGENT_STAT, GLOBAL_SENDER,
};
use injection::{create_memfd_with_data, inject_to_process, watch_and_inject, AGENT_SO};
use crate::logger::{DIM, GREEN, RED, RESET, YELLOW};
use libc::close;
use repl::{print_help, run_js_repl, CommandCompleter};
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::sync::atomic::Ordering;
use types::get_string_table_names;

/// 通过读 /proc/*/cmdline 按进程名查找 PID。
/// 精确匹配（含末路径组件）；多匹配列出并返回错误。
fn find_pid_by_name(name: &str) -> Result<i32, String> {
    use std::fs;

    let mut matches: Vec<i32> = Vec::new();
    let proc_dir = fs::read_dir("/proc").map_err(|e| format!("读取 /proc 失败: {}", e))?;

    for entry in proc_dir.flatten() {
        let fname = entry.file_name();
        let fname_str = fname.to_string_lossy();
        if !fname_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid: i32 = match fname_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        if let Ok(data) = fs::read(&cmdline_path) {
            let proc_name = data
                .split(|&b| b == 0)
                .next()
                .and_then(|s| std::str::from_utf8(s).ok())
                .unwrap_or("");
            let base_name = proc_name.rsplit('/').next().unwrap_or(proc_name);
            if proc_name == name || base_name == name {
                matches.push(pid);
            }
        }
    }

    match matches.len() {
        0 => Err(format!("未找到进程名匹配 '{}'", name)),
        1 => Ok(matches[0]),
        _ => {
            log_warn!("找到多个匹配进程，请使用 --pid 指定:");
            for pid in &matches {
                let cmdline_path = format!("/proc/{}/cmdline", pid);
                let display = if let Ok(data) = std::fs::read(&cmdline_path) {
                    data.split(|&b| b == 0)
                        .filter(|s| !s.is_empty())
                        .take(2)
                        .flat_map(|s| std::str::from_utf8(s))
                        .collect::<Vec<_>>()
                        .join(" ")
                } else {
                    "?".to_string()
                };
                println!("  PID {:6}: {}", pid, display);
            }
            Err(format!(
                "找到 {} 个匹配进程，请使用 --pid <n> 精确指定",
                matches.len()
            ))
        }
    }
}

fn main() {
    // Fix #8: 先解析参数（--help/--version 在此退出），再打印 banner
    let args = Args::parse();
    logger::print_banner();

    // 初始化 verbose 模式
    logger::VERBOSE.store(args.verbose, Ordering::Relaxed);

    // 初始化 agent.so 的 memfd
    match create_memfd_with_data("wwb_so", AGENT_SO) {
        Ok(fd) => {
            AGENT_MEMFD.store(fd, Ordering::SeqCst);
            log_verbose!("已创建 agent.so memfd: {}", fd);
            log_success!("agent.so 已就绪");
        }
        Err(e) => {
            log_error!("创建 agent.so memfd 失败: {}", e);
            std::process::exit(1);
        }
    }

    // 解析 --name 到 PID（如果指定）
    let target_pid: Option<i32> = if let Some(ref name) = args.name {
        match find_pid_by_name(name) {
            Ok(pid) => {
                log_success!("按名称 '{}' 找到进程 PID: {}", name, pid);
                Some(pid)
            }
            Err(e) => {
                log_error!("{}", e);
                std::process::exit(1);
            }
        }
    } else {
        args.pid
    };

    // 计算动态 socket 名（按目标 PID 或宿主 PID 区分实例，避免多实例冲突）
    let socket_name = if let Some(pid) = target_pid {
        format!("rust_frida_{}", pid)
    } else {
        // --watch-so: 目标 PID 注入时才知道，用宿主 PID 保证唯一性
        format!("rust_frida_h{}", std::process::id())
    };

    // 解析字符串覆盖参数（格式：name=value）
    let mut string_overrides = std::collections::HashMap::new();
    let available_names = get_string_table_names();

    for s in &args.strings {
        if let Some((name, value)) = s.split_once('=') {
            if available_names.contains(&name) {
                string_overrides.insert(name.to_string(), value.to_string());
            } else {
                log_warn!(
                    "未知的字符串名称 '{}', 可用名称: {}",
                    name,
                    available_names.join(", ")
                );
            }
        } else {
            log_warn!("无效的字符串格式 '{}', 应为 name=value", s);
        }
    }

    // 打印字符串覆盖信息
    if !string_overrides.is_empty() {
        log_info!("字符串覆盖列表 ({} 个):", string_overrides.len());
        for (name, value) in &string_overrides {
            println!("     {} = {}", name, value);
        }
    }

    // 自动写入动态 socket_name（用户未通过 --string 覆盖时）
    if !string_overrides.contains_key("socket_name") {
        string_overrides.insert("socket_name".to_string(), socket_name.clone());
    }

    // Fix #5: 注入前检测是否已有 agent 连接（另一个 rustfrida 实例正在运行）
    if check_agent_running(&socket_name) {
        log_warn!("警告: 检测到已有 agent 连接，目标进程可能已被注入！");
        log_warn!("继续注入可能导致多个 agent 并存，建议先终止旧会话");
    }

    // 启动抽象套接字监听（失败立即退出，不执行后续注入）
    let handle = start_socket_listener(&socket_name).unwrap_or_else(|e| {
        log_error!("启动 socket 监听失败: {}", e);
        std::process::exit(1);
    });

    // 根据参数选择注入方式
    let result = if let Some(so_pattern) = &args.watch_so {
        // 使用 eBPF 监听 SO 加载
        watch_and_inject(so_pattern, args.timeout, &string_overrides)
    } else if let Some(pid) = target_pid {
        // 直接附加到指定 PID（来自 --pid 或 --name 解析结果）
        inject_to_process(pid, &string_overrides)
    } else {
        log_error!("必须指定 --pid、--name 或 --watch-so");
        std::process::exit(1);
    };

    if let Err(e) = result {
        log_error!("注入失败: {}", e);
        std::process::exit(1);
    }

    // 等待 agent 连接，默认超时 30s（可通过 --connect-timeout 调整）
    {
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_secs(args.connect_timeout);
        log_info!("等待 agent 连接... (最长 {}s)", args.connect_timeout);
        while !AGENT_STAT.load(Ordering::Acquire) {
            if std::time::Instant::now() >= deadline {
                log_error!(
                    "等待 agent 连接超时 ({}s)，请检查:",
                    args.connect_timeout
                );
                // 检查目标进程是否仍在运行
                if let Some(pid) = target_pid {
                    if std::path::Path::new(&format!("/proc/{}/status", pid)).exists() {
                        log_warn!("  目标进程 {} 仍在运行（agent 可能崩溃或未加载）", pid);
                    } else {
                        log_warn!("  目标进程 {} 已退出（可能被 OOM 或信号终止）", pid);
                    }
                }
                log_warn!("  1. dmesg | grep -i 'deny\\|avc'  （SELinux 拦截？）");
                log_warn!("  2. logcat | grep -E 'FATAL|crash'  （agent 崩溃？）");
                log_warn!("  3. 使用 --verbose 重新运行查看详细注入日志");
                log_warn!("  4. adb logcat | grep rustFrida  （查看 agent 日志）");
                std::process::exit(1);
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
    let sender = GLOBAL_SENDER.get().unwrap();

    // Fix #2 & #7: --load-script 用 eval_state 等待 jsinit/loadjs 确认，而非 sleep(1)
    if let Some(script_path) = &args.load_script {
        match std::fs::read_to_string(script_path) {
            Ok(script) => {
                log_info!("加载脚本: {}", script_path);

                // 等待 jsinit 确认引擎就绪
                eval_state().clear();
                if let Err(e) = sender.send("jsinit".to_string()) {
                    log_error!("发送 jsinit 失败: {}", e);
                } else {
                    match eval_state().recv_timeout(std::time::Duration::from_secs(10)) {
                        None => log_warn!("等待引擎初始化超时"),
                        Some(Err(e)) => log_error!("引擎初始化失败: {}", e),
                        Some(Ok(_)) => {
                            // 引擎就绪，发送脚本
                            // 用 \r 替换 \n 避免按行分割协议误判（JS 将 \r 视为行终止符）
                            let script_line = script.replace('\n', "\r");
                            eval_state().clear();
                            let cmd = format!("loadjs {}", script_line);
                            if let Err(e) = sender.send(cmd) {
                                log_error!("发送 loadjs 失败: {}", e);
                            } else {
                                // 等待脚本执行结果
                                match eval_state().recv_timeout(std::time::Duration::from_secs(30))
                                {
                                    None => log_warn!("等待脚本执行结果超时"),
                                    Some(Ok(output)) => {
                                        if !output.is_empty() {
                                            println!("{GREEN}=> {}{RESET}", output);
                                        }
                                    }
                                    Some(Err(err)) => {
                                        println!("{RED}[JS error] {}{RESET}", err)
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                log_error!("读取脚本文件 '{}' 失败: {}", script_path, e);
            }
        }
    }

    let mut rl = match Editor::new() {
        Ok(e) => e,
        Err(e) => {
            log_error!("初始化行编辑器失败: {}", e);
            std::process::exit(1);
        }
    };
    rl.set_helper(Some(CommandCompleter::new()));
    let _ = rl.load_history(".rustfrida_history");
    println!("  {DIM}输入 help 查看命令，exit 退出{RESET}");

    // 发送 shutdown 到 agent 并短暂等待消息送达
    let send_shutdown = |s: &std::sync::mpsc::Sender<String>| {
        let _ = s.send("shutdown".to_string());
        std::thread::sleep(std::time::Duration::from_millis(300));
    };

    loop {
        // 检测 agent 是否已断连（agent 崩溃或目标进程被杀）
        if AGENT_DISCONNECTED.load(Ordering::Acquire) {
            log_error!("Agent 连接已断开，请重新注入");
            break;
        }

        match rl.readline("rustfrida> ") {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(&line);
                if line == "help" {
                    print_help();
                    continue;
                }
                if line == "exit" || line == "quit" {
                    log_info!("退出交互模式");
                    // Fix #4: 退出前通知 agent 清理并退出
                    send_shutdown(sender);
                    break;
                }
                if line == "jsrepl" {
                    run_js_repl(sender);
                    continue;
                }
                // 校验 hfl/qfl 必须带 <module> <offset> 两个参数
                {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if matches!(parts.first().copied(), Some("hfl") | Some("qfl"))
                        && parts.len() < 3
                    {
                        log_warn!("用法: {} <module> <offset>", parts[0]);
                        continue;
                    }
                }
                // Fix #1: loadjs/jseval/jsinit 都等待 EVAL:/EVAL_ERR: 响应并显示结果
                // jsinit 也走 eval 等待，避免其 EVAL:initialized 响应污染后续 jseval 通道
                let is_eval_cmd = line.starts_with("jseval ")
                    || line.starts_with("loadjs ")
                    || line == "jsinit"
                    || line == "jsclean";
                if is_eval_cmd {
                    eval_state().clear();
                }
                match sender.send(line) {
                    Ok(_) => {}
                    Err(e) => {
                        log_error!("发送命令失败: {}", e);
                        break;
                    }
                }
                if is_eval_cmd {
                    match eval_state().recv_timeout(std::time::Duration::from_secs(5)) {
                        None => println!("{YELLOW}[timeout] 等待执行结果超时{RESET}"),
                        Some(Ok(output)) => {
                            if !output.is_empty() {
                                println!("{GREEN}=> {}{RESET}", output);
                            }
                        }
                        Some(Err(err)) => println!("{RED}[JS error] {}{RESET}", err),
                    }
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                log_info!("退出交互模式");
                send_shutdown(sender);
                break;
            }
            Err(e) => {
                log_error!("读取输入失败: {}", e);
                break;
            }
        }
    }

    let _ = rl.save_history(".rustfrida_history");

    // 通知监听线程退出（防止 agent 从未连接时 join 永久阻塞）
    communication::STOP_LISTENER.store(true, Ordering::SeqCst);
    // 等待监听线程退出
    handle.join().unwrap();

    // 清理资源
    let memfd = AGENT_MEMFD.load(Ordering::SeqCst);
    if memfd >= 0 {
        unsafe { close(memfd) };
        log_success!("已关闭 agent.so memfd");
    }
}
