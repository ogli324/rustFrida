//! Recomp 页管理回调桥

use std::sync::Mutex;

type RecompHandler = fn(usize) -> Result<usize, String>;
type RecompAllocSlotHandler = fn(usize) -> Result<usize, String>;

static HANDLER: Mutex<Option<RecompHandler>> = Mutex::new(None);
static ALLOC_SLOT_HANDLER: Mutex<Option<RecompAllocSlotHandler>> = Mutex::new(None);

pub fn set_handler(handler: RecompHandler) {
    *HANDLER.lock().unwrap() = Some(handler);
}

pub fn set_alloc_slot_handler(handler: RecompAllocSlotHandler) {
    *ALLOC_SLOT_HANDLER.lock().unwrap() = Some(handler);
}

pub fn ensure_and_translate(orig_addr: usize) -> Result<usize, String> {
    let guard = HANDLER.lock().unwrap();
    let handler = match guard.as_ref() {
        Some(h) => h,
        None => return Err("recomp handler not set".into()),
    };
    handler(orig_addr)
}

/// 分配 recomp 跳板 slot + 写 B 指令到 recomp 代码页
pub fn alloc_trampoline_slot(orig_addr: usize) -> Result<usize, String> {
    let guard = ALLOC_SLOT_HANDLER.lock().unwrap();
    let handler = match guard.as_ref() {
        Some(h) => h,
        None => return Err("recomp alloc_slot handler not set".into()),
    };
    handler(orig_addr)
}
