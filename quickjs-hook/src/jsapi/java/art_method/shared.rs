// ============================================================================
// 共享 Runtime 布局辅助函数
// ============================================================================

/// 根据 API 级别和 java_vm_ 偏移计算 classLinker_ 在 Runtime 中的候选偏移列表。
///
/// 共享于 find_classlinker_trampolines 和 probe_art_runtime_spec。
/// 对标 Frida android.js:649-662。
fn compute_classlinker_candidates(java_vm_off: usize) -> Vec<usize> {
    const STD_STRING_SIZE: usize = 3 * 8;
    const PTR_SIZE: usize = 8;

    let api_level = get_android_api_level();
    let codename = get_android_codename();
    let is_34_equiv = is_api_level_34_or_apex_equivalent();

    if api_level >= 33 || codename == "Tiramisu" || is_34_equiv {
        vec![java_vm_off - 4 * PTR_SIZE]
    } else if api_level >= 30 || codename == "R" || codename == "S" {
        vec![java_vm_off - 3 * PTR_SIZE, java_vm_off - 4 * PTR_SIZE]
    } else if api_level >= 29 || codename == "Q" {
        vec![java_vm_off - 2 * PTR_SIZE]
    } else if api_level >= 27 {
        vec![java_vm_off - STD_STRING_SIZE - 3 * PTR_SIZE]
    } else {
        vec![java_vm_off - STD_STRING_SIZE - 2 * PTR_SIZE]
    }
}

// ============================================================================
// ArtField layout — 按 API level 硬编码 (对标 Frida getArtFieldSpec)
// ============================================================================

/// ArtField 结构体字段偏移规格
#[allow(dead_code)]
pub(super) struct ArtFieldSpec {
    pub size: usize,
    pub access_flags_offset: usize,
}

#[allow(dead_code)]
static ART_FIELD_SPEC: OnceLock<Option<ArtFieldSpec>> = OnceLock::new();

/// 获取 ArtField 布局规格（按 API level 硬编码，对标 Frida getArtFieldSpec）
///
/// API >= 23 (Android 6+): size=16, access_flags_offset=4
/// API 21-22 (Android 5.x): size=24, access_flags_offset=12
/// API < 21: 不支持
#[allow(dead_code)]
pub(super) fn get_art_field_spec() -> Option<&'static ArtFieldSpec> {
    ART_FIELD_SPEC
        .get_or_init(|| {
            let api_level = get_android_api_level();
            if api_level >= 23 {
                Some(ArtFieldSpec {
                    size: 16,
                    access_flags_offset: 4,
                })
            } else if api_level >= 21 {
                Some(ArtFieldSpec {
                    size: 24,
                    access_flags_offset: 12,
                })
            } else {
                None
            }
        })
        .as_ref()
}
