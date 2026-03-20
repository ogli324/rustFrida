#![cfg(all(target_os = "android", target_arch = "aarch64"))]

mod args;
mod communication;
mod injection;
mod logger;
mod proc_mem;
mod process;
mod repl;
mod selinux;
mod spawn;
mod types;

use crate::logger::{DIM, RESET};
use args::Args;
use clap::Parser;
#[cfg(feature = "qbdi")]
use communication::send_qbdi_helper;
use communication::{
    eval_state, send_command, start_socketpair_handler, HostToAgentMessage, AGENT_DISCONNECTED, AGENT_STAT,
    GLOBAL_SENDER,
};
use injection::{inject_via_bootstrapper, watch_and_inject};
use process::find_pid_by_name;
use repl::{print_eval_result, print_help, run_js_repl, CommandCompleter};
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::os::unix::io::RawFd;
use std::sync::atomic::Ordering;
use types::get_string_table_names;

fn main() {
    // Fix #8: 先解析参数（--help/--version 在此退出），再打印 banner
    let args = Args::parse();
    logger::print_banner();

    // 初始化 verbose 模式
    logger::VERBOSE.store(args.verbose, Ordering::Relaxed);

    // 解析 --name 到 PID（如果指定）
    let resolved_pid: Option<i32> = if let Some(ref name) = args.name {
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

    // 解析字符串覆盖参数（格式：name=value）
    let mut string_overrides = std::collections::HashMap::new();
    let available_names = get_string_table_names();

    for s in &args.strings {
        if let Some((name, value)) = s.split_once('=') {
            if available_names.contains(&name) {
                string_overrides.insert(name.to_string(), value.to_string());
            } else {
                log_warn!("未知的字符串名称 '{}', 可用名称: {}", name, available_names.join(", "));
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

    // 根据参数选择注入方式，返回 (target_pid, host_fd)
    let (target_pid, host_fd): (Option<i32>, RawFd) = if let Some(ref package) = args.spawn {
        // Spawn 模式：注册信号处理函数，确保 Ctrl+C 时还原 Zygote patch
        spawn::register_cleanup_handler();
        // Spawn 模式：注入 Zygote 后启动 App
        match spawn::spawn_and_inject(package, &string_overrides) {
            Ok((pid, fd)) => (Some(pid), fd),
            Err(e) => {
                log_error!("Spawn 注入失败: {}", e);
                spawn::cleanup_zygote_patches();
                std::process::exit(1);
            }
        }
    } else if let Some(so_pattern) = &args.watch_so {
        // 使用 eBPF 监听 SO 加载
        match watch_and_inject(so_pattern, args.timeout, &string_overrides) {
            Ok(fd) => (resolved_pid, fd),
            Err(e) => {
                log_error!("注入失败: {}", e);
                std::process::exit(1);
            }
        }
    } else if let Some(pid) = resolved_pid {
        // 直接附加到指定 PID（来自 --pid 或 --name 解析结果）
        match inject_via_bootstrapper(pid, &string_overrides) {
            Ok(fd) => (Some(pid), fd),
            Err(e) => {
                log_error!("注入失败: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        log_error!("必须指定 --pid、--name、--watch-so 或 --spawn");
        std::process::exit(1);
    };

    // 启动 socketpair handler（在 host_fd 上读写）
    let handle = start_socketpair_handler(host_fd);

    // 等待 agent 连接，默认超时 30s（可通过 --connect-timeout 调整）
    {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(args.connect_timeout);
        log_info!("等待 agent 连接... (最长 {}s)", args.connect_timeout);
        while !AGENT_STAT.load(Ordering::Acquire) {
            // Spawn 模式：Ctrl+C 触发清理退出（100ms 轮询间隔内响应）
            if args.spawn.is_some() && spawn::signal_received() {
                log_info!("收到终止信号，正在清理...");
                spawn::cleanup_zygote_patches();
                std::process::exit(1);
            }
            if std::time::Instant::now() >= deadline {
                log_error!("等待 agent 连接超时 ({}s)，请检查:", args.connect_timeout);
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
                // Spawn 模式：超时前恢复子进程，防止永远卡在 recv(ACK)
                if let Some(pid) = target_pid {
                    if args.spawn.is_some() {
                        let _ = spawn::resume_child(pid as u32);
                    }
                }
                std::process::exit(1);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    let sender = GLOBAL_SENDER.get().unwrap();

    #[cfg(feature = "qbdi")]
    {
        if let Err(e) = send_qbdi_helper(sender, crate::injection::QBDI_HELPER_SO.to_vec()) {
            log_error!("发送 QBDI helper 失败: {}", e);
            std::process::exit(1);
        }
    }

    // Spawn 模式: jsinit → loadjs → resume
    //
    // 子进程在 setArgV0 阶段阻塞，ART 已完成基本 post-fork 初始化，
    // AttachCurrentThread 可用。jsinit + loadjs 在 resume 前完成所有 hook 安装。
    if let Some(ref _package) = args.spawn {
        if let Some(pid) = target_pid {
            if spawn::signal_received() {
                log_info!("收到终止信号，正在清理...");
                spawn::cleanup_zygote_patches();
                std::process::exit(1);
            }
            // 在子进程暂停时完成: jsinit + loadjs → 所有 hook 就位 → 再 resume
            if let Some(script_path) = &args.load_script {
                match std::fs::read_to_string(script_path) {
                    Ok(script) => {
                        log_info!("加载脚本 (子进程暂停中): {}", script_path);
                        eval_state().clear();
                        if let Err(e) = send_command(sender, "jsinit") {
                            log_error!("发送 jsinit 失败: {}", e);
                        } else {
                            match eval_state().recv_timeout(std::time::Duration::from_secs(10)) {
                                None => log_warn!("等待引擎初始化超时"),
                                Some(Err(e)) => log_error!("引擎初始化失败: {}", e),
                                Some(Ok(_)) => {
                                    let script_line = script.replace('\n', "\r");
                                    eval_state().clear();
                                    let cmd = format!("loadjs {}", script_line);
                                    if let Err(e) = send_command(sender, cmd) {
                                        log_error!("发送 loadjs 失败: {}", e);
                                    } else {
                                        print_eval_result(30);
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
            // resume: hook 已就位，恢复子进程
            if let Err(e) = spawn::resume_child(pid as u32) {
                log_error!("恢复子进程失败: {}", e);
            }
        }
    }

    // 非 spawn 模式: --load-script 在 resume 后加载（进程已在运行）
    if args.spawn.is_none() {
        if let Some(script_path) = &args.load_script {
            match std::fs::read_to_string(script_path) {
                Ok(script) => {
                    log_info!("加载脚本: {}", script_path);
                    eval_state().clear();
                    if let Err(e) = send_command(sender, "jsinit") {
                        log_error!("发送 jsinit 失败: {}", e);
                    } else {
                        match eval_state().recv_timeout(std::time::Duration::from_secs(10)) {
                            None => log_warn!("等待引擎初始化超时"),
                            Some(Err(e)) => log_error!("引擎初始化失败: {}", e),
                            Some(Ok(_)) => {
                                let script_line = script.replace('\n', "\r");
                                eval_state().clear();
                                let cmd = format!("loadjs {}", script_line);
                                if let Err(e) = send_command(sender, cmd) {
                                    log_error!("发送 loadjs 失败: {}", e);
                                } else {
                                    print_eval_result(30);
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

    // 发送 shutdown 到 agent，随后等待 agent 完整清理并主动关闭 socket
    let send_shutdown = |s: &std::sync::mpsc::Sender<HostToAgentMessage>| {
        if let Err(e) = send_command(s, "shutdown") {
            log_error!("发送 shutdown 失败: {}", e);
        } else {
            log_info!("已发送 shutdown，等待 agent 主动断开连接...");
        }
    };

    loop {
        // 检测 agent 是否已断连（agent 崩溃或目标进程被杀）
        if AGENT_DISCONNECTED.load(Ordering::Acquire) {
            log_error!("Agent 连接已断开，请重新注入");
            break;
        }

        // Spawn 模式：检测是否收到终止信号（信号处理函数仅设标记，清理在此退出路径完成）
        if args.spawn.is_some() && spawn::signal_received() {
            log_info!("收到终止信号，正在退出...");
            send_shutdown(sender);
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
                // 校验 hfl 必须带 <module> <offset> 两个参数
                {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if matches!(parts.first().copied(), Some("hfl")) && parts.len() < 3 {
                        log_warn!("用法: {} <module> <offset>", parts[0]);
                        continue;
                    }
                }
                // Fix #1: loadjs/jseval/jsinit 都等待 EVAL:/EVAL_ERR: 响应并显示结果
                // jsinit 也走 eval 等待，避免其 EVAL:initialized 响应污染后续 jseval 通道
                let is_recomp = line.starts_with("recomp");
                let is_eval_cmd =
                    line.starts_with("jseval ") || line.starts_with("loadjs ") || line == "jsinit" || line == "jsclean"
                    || is_recomp;
                if is_eval_cmd {
                    eval_state().clear();
                }
                match send_command(sender, line) {
                    Ok(_) => {}
                    Err(e) => {
                        log_error!("发送命令失败: {}", e);
                        break;
                    }
                }
                if is_eval_cmd {
                    print_eval_result(if is_recomp { 15 } else { 5 });
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

    // Spawn 模式：退出前还原 Zygote patch
    if args.spawn.is_some() {
        spawn::cleanup_zygote_patches();
    }

    // 等待 handler 线程退出（agent cleanup 完成后主动关闭 socket，host 收到 EOF 自然退出）
    let _ = handle.join();
}

