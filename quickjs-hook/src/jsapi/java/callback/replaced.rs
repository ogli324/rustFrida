// ============================================================================
// replacedMethods — 双向映射 original↔replacement ArtMethod
// ============================================================================
//
// 用于 artController 全局 DoCall hook 回调中查找 replacement。
// artController hooks ART 的 DoCall 函数（解释器路径），在 on_enter 回调中
// 通过此映射将 x0 (ArtMethod*) 从 original 替换为 replacement。
// 所有被 hook 方法均通过 per-method deoptimize 强制走解释器 → DoCall 路径。

/// 双向映射 original ArtMethod ↔ replacement ArtMethod
static REPLACED_METHODS: BiMap = BiMap::new();

/// 注册 original → replacement 映射（双向 + C 侧内联查表）
pub(in crate::jsapi::java) fn set_replacement_method(original: u64, replacement: u64) {
    REPLACED_METHODS.init();
    REPLACED_METHODS.insert(original, replacement);
    // 同步到 C 侧内联查表 (thunk 直接扫描，无需 Mutex+HashMap)
    unsafe {
        hook_ffi::hook_art_router_table_add(original, replacement);
    }
}

/// 查找 original 对应的 replacement（如果已注册）
pub(super) fn get_replacement_method(original: u64) -> Option<u64> {
    REPLACED_METHODS.get_forward(original)
}

/// 删除 original → replacement 映射（双向 + C 侧内联查表）
pub(super) fn delete_replacement_method(original: u64) {
    REPLACED_METHODS.remove_by_forward(original);
    // 同步到 C 侧内联查表
    unsafe {
        hook_ffi::hook_art_router_table_remove(original);
    }
}

/// 检查给定地址是否为 replacement ArtMethod
#[allow(dead_code)]
pub(super) fn is_replacement_method(method: u64) -> bool {
    REPLACED_METHODS.contains_reverse(method)
}

// NOTE: art_router_fn has been removed — routing is now done via inline
// g_art_router_table scan in the C-side thunk (no function call needed).
