//! Recomp stealth hook 桥接层
//!
//! 页管理在 agent 侧（mmap/prctl），本模块通过注册的回调访问。
//! JS API 的 hook("recomp") 模式通过本模块触发页重编译 + 地址翻译。

pub mod page;

pub use page::{alloc_trampoline_slot, ensure_and_translate, set_alloc_slot_handler, set_handler};
