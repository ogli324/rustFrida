use std::sync::atomic::{AtomicBool, Ordering};

/// 全局 verbose 开关（由 --verbose 标志控制）
pub static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// ANSI 颜色常量
pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";

pub const RED: &str = "\x1b[31m";
pub const GREEN: &str = "\x1b[32m";
pub const YELLOW: &str = "\x1b[33m";
pub const BLUE: &str = "\x1b[34m";
pub const MAGENTA: &str = "\x1b[35m";
pub const CYAN: &str = "\x1b[36m";

/// 256 色扩展常量（rustyline Highlighter 专用）
pub const GRAY: &str = "\x1b[38;5;245m";
pub const HIGHLIGHT_BG: &str = "\x1b[48;5;238m";
pub const HIGHLIGHT_FG: &str = "\x1b[38;5;255m";

/// [*] 蓝色前缀 - 通用信息
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {{
        println!("{}{} [*]{} {}", $crate::logger::BOLD, $crate::logger::BLUE, $crate::logger::RESET, format_args!($($arg)*));
    }};
}

/// [✓] 绿色前缀 - 成功操作
#[macro_export]
macro_rules! log_success {
    ($($arg:tt)*) => {{
        println!("{}{} [✓]{} {}", $crate::logger::BOLD, $crate::logger::GREEN, $crate::logger::RESET, format_args!($($arg)*));
    }};
}

/// [!] 黄色前缀 - 警告
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {{
        eprintln!("{}{} [!]{} {}", $crate::logger::BOLD, $crate::logger::YELLOW, $crate::logger::RESET, format_args!($($arg)*));
    }};
}

/// [✗] 红色前缀 - 错误（输出到 stderr）
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {{
        eprintln!("{}{} [✗]{} {}", $crate::logger::BOLD, $crate::logger::RED, $crate::logger::RESET, format_args!($($arg)*));
    }};
}

/// [→] 青色前缀 - 步骤/详细信息
#[macro_export]
macro_rules! log_step {
    ($($arg:tt)*) => {{
        println!("{}{} [→]{} {}", $crate::logger::BOLD, $crate::logger::CYAN, $crate::logger::RESET, format_args!($($arg)*));
    }};
}

/// 地址显示 - 带缩进的地址格式化
#[macro_export]
macro_rules! log_addr {
    ($label:expr, $addr:expr) => {{
        println!(
            "     {}: {}0x{:x}{}",
            $label,
            $crate::logger::DIM,
            $addr,
            $crate::logger::RESET
        );
    }};
}

/// [→] 仅 --verbose 时输出的详细步骤信息
#[macro_export]
macro_rules! log_verbose {
    ($($arg:tt)*) => {{
        if $crate::logger::is_verbose() {
            println!("{}{} [→]{} {}", $crate::logger::BOLD, $crate::logger::CYAN, $crate::logger::RESET, format_args!($($arg)*));
        }
    }};
}

/// 地址显示 - 仅 --verbose 时输出
#[macro_export]
macro_rules! log_verbose_addr {
    ($label:expr, $addr:expr) => {{
        if $crate::logger::is_verbose() {
            println!(
                "     {}: {}0x{:x}{}",
                $label,
                $crate::logger::DIM,
                $addr,
                $crate::logger::RESET
            );
        }
    }};
}

/// [agent] 紫色前缀 - 来自 agent 的消息
#[macro_export]
macro_rules! log_agent {
    ($($arg:tt)*) => {{
        println!("{}{} [agent]{} {}", $crate::logger::BOLD, $crate::logger::MAGENTA, $crate::logger::RESET, format_args!($($arg)*));
    }};
}

/// 打印 banner
pub fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    println!(
        "\n {BOLD}{CYAN}╔══════════════════════════════════════╗{RESET}\n \
         {BOLD}{CYAN}║{RESET}  {BOLD}      rustFrida v{version:<17} {RESET}{BOLD}{CYAN}║{RESET}\n \
         {BOLD}{CYAN}║{RESET}  {DIM}  ARM64 Dynamic Instrumentation    {RESET}{BOLD}{CYAN}║{RESET}\n \
         {BOLD}{CYAN}╚══════════════════════════════════════╝{RESET}\n"
    );
}
