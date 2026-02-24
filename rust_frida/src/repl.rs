#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{CompletionType, Config, Context, Editor, Helper};
use std::sync::mpsc::Sender;
use std::sync::OnceLock;

use crate::communication::{complete_state, eval_state};
use crate::log_error;
use crate::logger::{GRAY, GREEN, HIGHLIGHT_BG, HIGHLIGHT_FG, RED, RESET, YELLOW};

/// 当前构建实际可用的命令列表（编译时由 feature 控制）
pub(crate) fn commands() -> &'static [(&'static str, &'static str, &'static str)] {
    static CMDS: OnceLock<Vec<(&'static str, &'static str, &'static str)>> = OnceLock::new();
    CMDS.get_or_init(|| {
        #[allow(unused_mut)]
        let mut v: Vec<(&'static str, &'static str, &'static str)> = vec![
            ("trace", "[tid]", "ptrace 指令追踪"),
            ("jhook", "", "Java/JNI hooking"),
            ("jsinit", "", "初始化 QuickJS 引擎"),
            ("loadjs", "<script>", "执行 JavaScript 代码"),
            ("jseval", "<expr>", "求值 JS 表达式并显示结果"),
            ("jsclean", "", "清理 QuickJS 引擎"),
            ("jsrepl", "", "进入 JS REPL 模式（Tab 动态补全）"),
            ("help", "", "显示此帮助信息"),
            ("exit", "", "退出程序（quit 同效）"),
        ];
        #[cfg(feature = "frida-gum")]
        {
            v.push(("stalker", "[tid]", "Frida Stalker 追踪 [frida-gum ✓]"));
            v.push(("hfl", "<module> <offset>", "Interceptor hook 指定偏移 [frida-gum ✓]"));
        }
        #[cfg(not(feature = "frida-gum"))]
        {
            v.push(("stalker", "[tid]", "Frida Stalker 追踪 [--features frida-gum 启用]"));
            v.push(("hfl", "<module> <offset>", "Interceptor hook 指定偏移 [--features frida-gum 启用]"));
        }
        #[cfg(feature = "qbdi")]
        {
            v.push(("qfl", "<module> <offset>", "QBDI 追踪指定偏移 [qbdi ✓]"));
        }
        #[cfg(not(feature = "qbdi"))]
        {
            v.push(("qfl", "<module> <offset>", "QBDI 追踪指定偏移 [--features qbdi 启用]"));
        }
        v
    })
}

/// Tab 补全器：仅补全第一个 token（命令名）
pub(crate) struct CommandCompleter;

impl CommandCompleter {
    pub(crate) fn new() -> Self {
        CommandCompleter
    }
}

impl Completer for CommandCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        // 只在光标处于第一个 token 范围内时补全
        let before_cursor = &line[..pos];
        if before_cursor.contains(' ') {
            return Ok((pos, vec![]));
        }
        let prefix = before_cursor;
        let candidates: Vec<Pair> = commands()
            .iter()
            .filter(|(cmd, _, _)| cmd.starts_with(prefix))
            .map(|(cmd, _, _)| Pair {
                display: cmd.to_string(),
                replacement: cmd.to_string(),
            })
            .collect();
        Ok((0, candidates))
    }
}

impl Hinter for CommandCompleter {
    type Hint = String;
}
impl Highlighter for CommandCompleter {}
impl Validator for CommandCompleter {}
impl Helper for CommandCompleter {}

/// JS REPL 补全器：通过 socket 向 agent 发送 jscomplete 请求，同步等待结果。
struct JsReplCompleter {
    sender: Sender<String>,
    /// Cache the last completion results for the hinter to display
    last_candidates: std::cell::RefCell<(String, Vec<String>)>,
}

impl JsReplCompleter {
    fn new(sender: Sender<String>) -> Self {
        JsReplCompleter {
            sender,
            last_candidates: std::cell::RefCell::new((String::new(), vec![])),
        }
    }

    /// 向 agent 发送 jscomplete 请求，持锁等待响应（≤300 ms），避免竞态。
    fn fetch_completions(&self, prefix: &str) -> Vec<String> {
        let timeout = std::time::Duration::from_millis(300);
        let cmd = format!("jscomplete {}", prefix);
        let sender = self.sender.clone();
        // 持锁 clear + 发命令 + wait，原子消除竞态窗口
        complete_state()
            .clear_then_recv(timeout, || {
                let _ = sender.send(cmd);
            })
            .unwrap_or_default()
    }
}

impl Completer for JsReplCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let before_cursor = &line[..pos];

        // Determine the replacement start position.  After the last '.' we only
        // replace the property fragment, but we send the *full* before_cursor
        // (e.g. "console.l") so the agent can resolve the object and enumerate
        // its properties.
        let (start, query) = if let Some(dot_pos) = before_cursor.rfind('.') {
            // start is right after the dot so rustyline replaces only the property part
            (dot_pos + 1, before_cursor)
        } else {
            (0, before_cursor)
        };

        let names = self.fetch_completions(query);
        // Cache for hinter
        *self.last_candidates.borrow_mut() = (before_cursor.to_string(), names.clone());

        let candidates: Vec<Pair> = names
            .into_iter()
            .map(|name| Pair {
                display: name.clone(),
                replacement: name,
            })
            .collect();

        Ok((start, candidates))
    }
}

impl Hinter for JsReplCompleter {
    type Hint = String;
    fn hint(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> Option<String> {
        let before_cursor = &line[..pos];
        let cache = self.last_candidates.borrow();
        let (ref cached_prefix, ref candidates) = *cache;

        // Only show hint if the current input is a prefix of the cached query
        // and there are multiple candidates
        if candidates.len() <= 1 || cached_prefix.is_empty() {
            return None;
        }

        // Check if current input matches the cached prefix context
        if !cached_prefix.starts_with(before_cursor)
            && !before_cursor.starts_with(cached_prefix.as_str())
        {
            return None;
        }

        // Get the property fragment after the last dot
        let prop_part = if let Some(dot_pos) = before_cursor.rfind('.') {
            &before_cursor[dot_pos + 1..]
        } else {
            before_cursor
        };

        // Filter candidates that match current typing
        let matching: Vec<&String> = candidates
            .iter()
            .filter(|c| c.starts_with(prop_part) && c.as_str() != prop_part)
            .collect();

        if matching.is_empty() {
            return None;
        }

        // Build hint: show as " [debug|error|info|log|warn]"
        let hint_list = matching
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("|");
        Some(format!(" [{}]", hint_list))
    }
}
impl Highlighter for JsReplCompleter {
    fn highlight_hint<'h>(&self, hint: &'h str) -> std::borrow::Cow<'h, str> {
        std::borrow::Cow::Owned(format!("{GRAY}{hint}{RESET}"))
    }
    fn highlight_candidate<'c>(
        &self,
        candidate: &'c str,
        completion: CompletionType,
    ) -> std::borrow::Cow<'c, str> {
        if completion == CompletionType::List {
            std::borrow::Cow::Owned(format!("{HIGHLIGHT_BG}{HIGHLIGHT_FG}{candidate}{RESET}"))
        } else {
            std::borrow::Cow::Borrowed(candidate)
        }
    }
}
impl Validator for JsReplCompleter {}
impl Helper for JsReplCompleter {}

/// 打印命令帮助表
pub(crate) fn print_help() {
    use crate::logger::{BOLD, CYAN, DIM, GREEN, RESET, YELLOW};
    println!("\n{BOLD}{CYAN}可用命令:{RESET}");
    println!("{DIM}  {:<10} {:<22} {}{RESET}", "命令", "参数", "说明");
    println!("{DIM}  {:-<10} {:-<22} {:-<20}{RESET}", "", "", "");
    for (cmd, args, desc) in commands() {
        println!(
            "  {BOLD}{GREEN}{:<10}{RESET} {YELLOW}{:<22}{RESET} {}",
            cmd, args, desc
        );
    }
    println!();
    println!("{BOLD}{CYAN}JavaScript API（在 loadjs/jseval/jsrepl 中可用）:{RESET}");
    println!("{DIM}  console{RESET}      log/info/warn/error/debug");
    println!("{DIM}  ptr(addr){RESET}    创建指针对象，addr 为数字或十六进制字符串");
    println!("{DIM}  Memory{RESET}       .readU8/16/32/64(ptr)  → number");
    println!("{DIM}             {RESET}  .readPointer(ptr)      → ptr");
    println!("{DIM}             {RESET}  .readCString(ptr)      → string（最多 4096 字节）");
    println!("{DIM}             {RESET}  .readByteArray(ptr, n) → ArrayBuffer");
    println!("{DIM}             {RESET}  .writeU8/16/32/64(ptr, val)");
    println!("{DIM}             {RESET}  .writePointer(ptr, val)");
    println!("{DIM}             {RESET}  无效地址抛 RangeError，不会 crash");
    println!("{DIM}  hook{RESET}         hook(target_ptr, replacement_ptr[, retval])");
    println!("{DIM}             {RESET}  replacement_ptr 为 JS 函数或 NativePointer");
    println!("{DIM}  unhook{RESET}       unhook(target_ptr)");
    println!("{DIM}  callNative{RESET}   callNative(addr, retType, argTypes, ...args)");
    println!("{DIM}             {RESET}  retType/argType: 'void'|'int'|'long'|'ptr'|'float'");
    println!("{DIM}  示例:{RESET}");
    println!("{DIM}    jseval Memory.readCString(ptr(0x7f000000)){RESET}");
    println!("{DIM}    loadjs hook(ptr(0x1234), function(ctx){{console.log('hit')}}){RESET}");
    println!();
}

/// Enter an interactive JS REPL mode.
///
/// Every line is sent as `loadjs <line>` to the agent.  Tab completion
/// queries the live QuickJS global scope via `jscomplete`.
/// Type `exit` or press Ctrl-D / Ctrl-C to return to the main prompt.
pub(crate) fn run_js_repl(sender: &Sender<String>) {
    use crate::logger::{BOLD, CYAN, DIM, RESET};

    // Auto-initialize JS engine: send jsinit and wait for EVAL confirmation.
    // Accept both Ok (just initialized) and Err containing "已初始化" (already was ready).
    {
        let result = eval_state().clear_then_recv(std::time::Duration::from_secs(5), || {
            let _ = sender.send("jsinit".to_string());
        });
        match result {
            None => {
                log_error!("jsrepl: jsinit 超时，JS 引擎未就绪");
                return;
            }
            Some(Ok(_)) => {}
            Some(Err(ref e)) if e.contains("已初始化") => {}
            Some(Err(e)) => {
                log_error!("jsrepl: jsinit 失败: {}", e);
                return;
            }
        }
    }

    println!("\n{BOLD}{CYAN}进入 JS REPL 模式{RESET} {DIM}(输入 exit 或按 Ctrl-D 退出){RESET}\n");

    // Clone the sender so JsReplCompleter can own it
    let sender_clone = sender.clone();
    let config = Config::builder()
        .completion_type(CompletionType::Circular)
        .build();
    let mut rl: Editor<JsReplCompleter, _> = match Editor::with_config(config) {
        Ok(e) => e,
        Err(e) => {
            log_error!("初始化 JS REPL 行编辑器失败: {}", e);
            return;
        }
    };
    rl.set_helper(Some(JsReplCompleter::new(sender_clone)));
    let _ = rl.load_history(".rustfrida_js_history");

    loop {
        match rl.readline("js> ") {
            Ok(line) => {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(&line);
                if line == "exit" || line == "quit" {
                    println!("{DIM}退出 JS REPL 模式{RESET}");
                    break;
                }
                // 发送前清空 eval 状态
                eval_state().clear();
                let cmd = format!("loadjs {}", line);
                if let Err(e) = sender.send(cmd) {
                    log_error!("发送 JS 命令失败: {}", e);
                    break;
                }
                // 同步等待 agent 返回结果（最长 5 秒）
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
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                println!("{DIM}退出 JS REPL 模式{RESET}");
                break;
            }
            Err(e) => {
                log_error!("读取 JS REPL 输入失败: {}", e);
                break;
            }
        }
    }
    let _ = rl.save_history(".rustfrida_js_history");
}
