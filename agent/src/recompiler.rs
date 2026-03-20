//! ARM64 页级代码重编译器
//!
//! 用户层职责：
//!   1. 读取原始页代码
//!   2. 重编译到新地址（调整 PC 相对指令）
//!   3. prctl(PR_RECOMPILE_REGISTER) 注册映射
//!
//! 内核层职责（不在本模块）：
//!   - 去掉原始页的 X 权限
//!   - 捕获执行异常，修改 PC 跳转到重编译页（同偏移）
//!
//! 用途：stealth hook — 在重编译页上修改代码，原始页不变。

use crate::communication::log_msg;
use crate::vma_name::set_anon_vma_name_raw;
use libc::{
    mmap, mprotect, munmap, sysconf, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE,
    _SC_PAGESIZE,
};
use std::collections::HashMap;
use std::io::Error;
use std::ptr;
use std::sync::Mutex;

type Result<T> = std::result::Result<T, String>;

// 内核 prctl 接口
const PR_RECOMPILE_REGISTER: i32 = 0x52430001;
const PR_RECOMPILE_RELEASE: i32 = 0x52430002;

const PAGE_SIZE: usize = 4096;
const TRAMPOLINE_PAGES: usize = 4; // 每个重编译页最多 4 页跳板空间

static VMA_RECOMP_CODE: &[u8] = b"wwb_recomp_code\0";
static VMA_RECOMP_TRAMP: &[u8] = b"wwb_recomp_tramp\0";

// C FFI
extern "C" {
    fn recompile_page(
        orig_code: *const u8,
        orig_base: u64,
        recomp_buf: *mut u8,
        recomp_base: u64,
        tramp_buf: *mut u8,
        tramp_base: u64,
        tramp_cap: usize,
        tramp_used: *mut usize,
        stats: *mut RecompileStatsC,
    ) -> i32;

    fn hook_flush_cache(start: *mut libc::c_void, size: usize);
    fn hook_write_jump(dst: *mut libc::c_void, target: *mut libc::c_void) -> i32;
}

/// C 侧的 RecompileStats 对应结构
#[repr(C)]
struct RecompileStatsC {
    num_copied: i32,
    num_intra_page: i32,
    num_direct_reloc: i32,
    num_trampolines: i32,
    error: i32,
    error_msg: [u8; 256],
}

impl RecompileStatsC {
    fn new() -> Self {
        RecompileStatsC {
            num_copied: 0,
            num_intra_page: 0,
            num_direct_reloc: 0,
            num_trampolines: 0,
            error: 0,
            error_msg: [0u8; 256],
        }
    }
}

/// 重编译统计信息
pub struct RecompileStats {
    pub num_copied: i32,
    pub num_intra_page: i32,
    pub num_direct_reloc: i32,
    pub num_trampolines: i32,
}

impl From<&RecompileStatsC> for RecompileStats {
    fn from(c: &RecompileStatsC) -> Self {
        RecompileStats {
            num_copied: c.num_copied,
            num_intra_page: c.num_intra_page,
            num_direct_reloc: c.num_direct_reloc,
            num_trampolines: c.num_trampolines,
        }
    }
}

/// 一个已重编译的页
struct RecompiledPage {
    /// 原始页基地址（用于内核注销时传参）
    #[allow(dead_code)]
    orig_base: usize,
    /// 重编译区域基地址（包含重编译页 + 跳板区）
    recomp_ptr: *mut u8,
    /// 重编译区域总大小
    recomp_total_size: usize,
    /// 跳板区已使用字节数
    tramp_used: usize,
    /// 是否已在内核注册
    registered: bool,
}

// SAFETY: 指针只在当前进程内使用，由 Mutex 保护
unsafe impl Send for RecompiledPage {}

/// 全局重编译页管理器
static RECOMP_PAGES: Mutex<Option<HashMap<usize, RecompiledPage>>> = Mutex::new(None);

fn ensure_init() {
    let mut guard = RECOMP_PAGES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
}

/// 重编译指定地址所在的页
///
/// - `addr`: 页内任意地址（自动对齐到页边界）
/// - `pid`: 目标进程 pid（0 = 当前进程）
///
/// 返回重编译页的基地址和统计信息
pub fn recompile(addr: usize, pid: u32) -> Result<(usize, RecompileStats)> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);

    // 检查是否已重编译
    {
        let guard = RECOMP_PAGES.lock().unwrap();
        if let Some(ref pages) = *guard {
            if pages.contains_key(&orig_base) {
                return Err(format!("页 0x{:x} 已重编译", orig_base));
            }
        }
    }

    // 重编译（共享 do_recompile_temp 逻辑）
    let t = do_recompile_temp(orig_base)?;

    // 接管 mmap 所有权（阻止 TempRecomp::drop 释放）
    let recomp_ptr = t.recomp_ptr;
    let recomp_base = t.recomp_base;
    let total_size = t.total_size;
    let tramp_used = t.tramp_used;
    let stats = RecompileStats::from(&t.stats);
    std::mem::forget(t); // 所有权转移到 RecompiledPage

    // 命名 VMA
    let tramp_ptr = unsafe { recomp_ptr.add(PAGE_SIZE) };
    let _ = set_anon_vma_name_raw(recomp_ptr, PAGE_SIZE, VMA_RECOMP_CODE);
    let _ = set_anon_vma_name_raw(tramp_ptr, TRAMPOLINE_PAGES * PAGE_SIZE, VMA_RECOMP_TRAMP);

    // 刷新 icache + 设为 R-X
    unsafe {
        hook_flush_cache(recomp_ptr as *mut _, total_size);
        mprotect(recomp_ptr as *mut _, total_size, PROT_READ | PROT_EXEC);
    }

    log_msg(format!(
        "[recompiler] 0x{:x} → 0x{:x} | copied={} intra={} reloc={} tramp={} tramp_bytes={}",
        orig_base,
        recomp_base,
        stats.num_copied,
        stats.num_intra_page,
        stats.num_direct_reloc,
        stats.num_trampolines,
        tramp_used,
    ));

    // 注册到内核（pid=0 表示当前进程，内核只接受 0）
    let prctl_ret = unsafe {
        libc::prctl(
            PR_RECOMPILE_REGISTER,
            0u64,
            orig_base as u64,
            recomp_base,
            0u64,
        )
    };

    let registered = if prctl_ret != 0 {
        log_msg(format!(
            "[recompiler] prctl 注册失败: {} (可能内核不支持)",
            Error::last_os_error()
        ));
        false
    } else {
        log_msg(format!(
            "[recompiler] prctl 注册成功: 0x{:x} → 0x{:x}",
            orig_base, recomp_base
        ));
        true
    };

    // 保存记录
    let page = RecompiledPage {
        orig_base,
        recomp_ptr,
        recomp_total_size: total_size,
        tramp_used,
        registered,
    };

    {
        let mut guard = RECOMP_PAGES.lock().unwrap();
        guard.as_mut().unwrap().insert(orig_base, page);
    }

    Ok((recomp_base as usize, stats))
}

/// 释放重编译页
pub fn release(addr: usize, pid: u32) -> Result<()> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);

    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_mut().unwrap();

    let page = pages
        .remove(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;

    // 从内核注销（pid=0 表示当前进程）
    if page.registered {
        unsafe {
            libc::prctl(
                PR_RECOMPILE_RELEASE,
                0u64,
                orig_base as u64,
                0u64,
                0u64,
            );
        }
    }

    // 释放内存
    unsafe {
        munmap(page.recomp_ptr as *mut _, page.recomp_total_size);
    }

    log_msg(format!("[recompiler] 释放 0x{:x}", orig_base));
    Ok(())
}

/// 获取重编译页的可写指针（用于 hook 修改代码）
///
/// 调用方负责：修改前 mprotect RWX，修改后 mprotect RX + flush icache
pub fn get_recomp_ptr(addr: usize) -> Result<*mut u8> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);

    let guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_ref().unwrap();

    let page = pages
        .get(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;

    Ok(page.recomp_ptr)
}

/// 确保地址所在页已重编译，返回翻译后的地址
/// 供 quickjs-hook 的 JS hook API 通过回调调用
pub fn ensure_and_translate(addr: usize) -> Result<usize> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);

    // 如果还没重编译，先重编译
    let need_recomp = {
        let guard = RECOMP_PAGES.lock().unwrap();
        !guard.as_ref().unwrap().contains_key(&orig_base)
    };

    if need_recomp {
        recompile(addr, 0)?;
    }

    translate_addr(addr)
}

/// 获取地址在重编译页中的对应地址
pub fn translate_addr(addr: usize) -> Result<usize> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);
    let offset = addr - orig_base;

    let guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_ref().unwrap();

    let page = pages
        .get(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;

    Ok(page.recomp_ptr as usize + offset)
}

/// 在重编译页上 patch 指令
///
/// `addr`: 原始地址（自动翻译到重编译页对应偏移）
/// `insns`: 要写入的指令（u32 数组）
pub fn patch_insns(addr: usize, insns: &[u32]) -> Result<()> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);
    let offset = addr - orig_base;

    let guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_ref().unwrap();

    let page = pages
        .get(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;

    let patch_size = insns.len() * 4;
    if offset + patch_size > PAGE_SIZE {
        return Err("patch 超出页边界".into());
    }

    unsafe {
        // 临时加写权限
        mprotect(
            page.recomp_ptr as *mut _,
            page.recomp_total_size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
        );

        // 写入指令
        let dst = page.recomp_ptr.add(offset) as *mut u32;
        for (i, &insn) in insns.iter().enumerate() {
            ptr::write_volatile(dst.add(i), insn);
        }

        // 刷新 icache
        hook_flush_cache(page.recomp_ptr.add(offset) as *mut _, patch_size);

        // 恢复权限
        mprotect(
            page.recomp_ptr as *mut _,
            page.recomp_total_size,
            PROT_READ | PROT_EXEC,
        );
    }

    Ok(())
}

/// 在 recomp 页的跳板区分配 slot 并写入跳转，在代码页写 B 指令。
///
/// 保持 recomp 页 offset 一一对应：代码页只改 1 条指令（B tramp_slot），
/// 完整跳转（ADRP+ADD+BR 或 MOVZ+MOVK+BR）写在跳板区。
///
/// `orig_addr`: 原始代码地址（自动翻译到 recomp 页偏移）
/// `jump_dest`: 跳转目标（如 router thunk）
/// 返回 recomp 页内被 patch 的地址（供调用方记录）
pub fn patch_with_trampoline(orig_addr: usize, jump_dest: usize) -> Result<usize> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = orig_addr & !(page_size - 1);
    let offset = orig_addr - orig_base;

    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_mut().unwrap();

    let page = pages
        .get_mut(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;

    // 跳板区在 recomp 页之后 (recomp_ptr + PAGE_SIZE)
    let tramp_base = unsafe { page.recomp_ptr.add(PAGE_SIZE) };
    let tramp_cap = TRAMPOLINE_PAGES * PAGE_SIZE;
    let slot_size = 20usize; // ADRP+ADD+BR (12) 或 MOVZ+MOVK+BR (16)，留 20 足够
    if page.tramp_used + slot_size > tramp_cap {
        return Err("recomp 跳板区已满".into());
    }

    let slot_ptr = unsafe { tramp_base.add(page.tramp_used) };
    let slot_addr = slot_ptr as usize;

    unsafe {
        // 临时加写权限
        mprotect(
            page.recomp_ptr as *mut _,
            page.recomp_total_size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
        );

        // 1. 在跳板 slot 写 full jump → jump_dest
        let jump_len = hook_write_jump(slot_ptr as *mut _, jump_dest as *mut _);
        if jump_len <= 0 {
            mprotect(page.recomp_ptr as *mut _, page.recomp_total_size, PROT_READ | PROT_EXEC);
            return Err(format!("hook_write_jump failed: {}", jump_len));
        }

        // 2. 在 recomp 代码页写 B slot（ARM64 B imm26: ±128MB）
        let recomp_code_addr = page.recomp_ptr.add(offset) as usize;
        let b_offset = (slot_addr as i64) - (recomp_code_addr as i64);
        if b_offset < -(1 << 27) || b_offset >= (1 << 27) {
            mprotect(page.recomp_ptr as *mut _, page.recomp_total_size, PROT_READ | PROT_EXEC);
            return Err(format!("B 指令范围超限: offset={}", b_offset));
        }
        let b_imm26 = ((b_offset >> 2) & 0x3FF_FFFF) as u32;
        let b_insn: u32 = 0x14000000 | b_imm26;
        ptr::write_volatile(recomp_code_addr as *mut u32, b_insn);

        // 刷新 icache
        hook_flush_cache(slot_ptr as *mut _, jump_len as usize);
        hook_flush_cache(recomp_code_addr as *mut _, 4);

        // 恢复权限
        mprotect(
            page.recomp_ptr as *mut _,
            page.recomp_total_size,
            PROT_READ | PROT_EXEC,
        );
    }

    page.tramp_used += slot_size;
    Ok(unsafe { page.recomp_ptr.add(offset) as usize })
}

/// 在 recomp 跳板区分配 slot，在 recomp 代码页写 B 指令指向 slot。
/// 返回 slot 地址（hook engine 后续在 slot 上写 full jump→thunk）。
///
/// 调用链: recomp 代码页[offset] → B slot → (hook engine 写) full jump → thunk
pub fn alloc_trampoline_slot(orig_addr: usize) -> Result<usize> {
    ensure_init();

    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = orig_addr & !(page_size - 1);
    let offset = orig_addr - orig_base;

    let mut guard = RECOMP_PAGES.lock().unwrap();
    let pages = guard.as_mut().unwrap();

    let page = pages
        .get_mut(&orig_base)
        .ok_or_else(|| format!("页 0x{:x} 未重编译", orig_base))?;

    // 跳板区在 recomp 页之后
    let tramp_base = unsafe { page.recomp_ptr.add(PAGE_SIZE) };
    let tramp_cap = TRAMPOLINE_PAGES * PAGE_SIZE;
    let slot_size = 32usize; // 预留足够空间给 hook engine 写 full jump + trampoline
    if page.tramp_used + slot_size > tramp_cap {
        return Err("recomp 跳板区已满".into());
    }

    let slot_ptr = unsafe { tramp_base.add(page.tramp_used) };
    let slot_addr = slot_ptr as usize;
    let recomp_code_addr = unsafe { page.recomp_ptr.add(offset) as usize };

    // B 指令范围检查 (±128MB)
    let b_offset = (slot_addr as i64) - (recomp_code_addr as i64);
    if b_offset < -(1 << 27) || b_offset >= (1 << 27) {
        return Err(format!("B 指令范围超限: offset={}", b_offset));
    }

    unsafe {
        // 临时加写权限
        mprotect(
            page.recomp_ptr as *mut _,
            page.recomp_total_size,
            PROT_READ | PROT_WRITE | PROT_EXEC,
        );

        // 在 recomp 代码页写 B slot
        let b_imm26 = ((b_offset >> 2) & 0x3FF_FFFF) as u32;
        let b_insn: u32 = 0x14000000 | b_imm26;
        ptr::write_volatile(recomp_code_addr as *mut u32, b_insn);

        hook_flush_cache(recomp_code_addr as *mut _, 4);

        // 恢复权限
        mprotect(
            page.recomp_ptr as *mut _,
            page.recomp_total_size,
            PROT_READ | PROT_EXEC,
        );
    }

    page.tramp_used += slot_size;
    Ok(slot_addr)
}

/// 临时重编译结果（mmap 分配 + C 重编译，不注册 prctl）
struct TempRecomp {
    orig_code: Vec<u8>,
    recomp_ptr: *mut u8,
    total_size: usize,
    recomp_base: u64,
    tramp_used: usize,
    stats: RecompileStatsC,
}

impl Drop for TempRecomp {
    fn drop(&mut self) {
        unsafe { munmap(self.recomp_ptr as *mut _, self.total_size) };
    }
}

fn do_recompile_temp(orig_base: usize) -> Result<TempRecomp> {
    let mut orig_code = vec![0u8; PAGE_SIZE];
    unsafe {
        ptr::copy_nonoverlapping(orig_base as *const u8, orig_code.as_mut_ptr(), PAGE_SIZE);
    }

    let total_size = PAGE_SIZE + TRAMPOLINE_PAGES * PAGE_SIZE;
    // hint 靠近原始页，确保 B 指令（±128MB）和 ADRP（±4GB）都在范围内
    let hint = (orig_base + PAGE_SIZE) as *mut libc::c_void;
    let recomp_ptr = unsafe {
        mmap(hint, total_size,
             PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    };
    if recomp_ptr == libc::MAP_FAILED {
        return Err(format!("mmap: {}", Error::last_os_error()));
    }
    let recomp_ptr = recomp_ptr as *mut u8;
    let recomp_base = recomp_ptr as u64;
    let tramp_ptr = unsafe { recomp_ptr.add(PAGE_SIZE) };
    let tramp_base = recomp_base + PAGE_SIZE as u64;
    let tramp_cap = TRAMPOLINE_PAGES * PAGE_SIZE;

    let mut tramp_used: usize = 0;
    let mut stats = RecompileStatsC::new();

    let ret = unsafe {
        recompile_page(
            orig_code.as_ptr(), orig_base as u64,
            recomp_ptr, recomp_base,
            tramp_ptr, tramp_base, tramp_cap,
            &mut tramp_used, &mut stats,
        )
    };

    if ret != 0 {
        let msg = std::str::from_utf8(&stats.error_msg).unwrap_or("?").trim_end_matches('\0');
        unsafe { munmap(recomp_ptr as *mut _, total_size) };
        return Err(format!("重编译失败: {}", msg));
    }

    Ok(TempRecomp { orig_code, recomp_ptr, total_size, recomp_base, tramp_used, stats })
}

/// Dry-run：只重编译不注册 prctl，对比原始 vs 重编译指令
pub fn dry_run(addr: usize) -> Result<String> {
    let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
    let orig_base = addr & !(page_size - 1);

    let t = do_recompile_temp(orig_base)?;

    let mut output = format!(
        "orig=0x{:x} recomp=0x{:x} delta=0x{:x}\n\
         copied={} intra={} reloc={} tramp={} tramp_bytes={}\n",
        orig_base, t.recomp_base,
        t.recomp_base.wrapping_sub(orig_base as u64),
        t.stats.num_copied, t.stats.num_intra_page,
        t.stats.num_direct_reloc, t.stats.num_trampolines, t.tramp_used
    );

    let orig_insns = unsafe { std::slice::from_raw_parts(t.orig_code.as_ptr() as *const u32, 1024) };
    let recomp_insns = unsafe { std::slice::from_raw_parts(t.recomp_ptr as *const u32, 1024) };

    let mut changed = 0;
    for i in 0..1024 {
        if orig_insns[i] != recomp_insns[i] {
            let off = i * 4;
            let recomp = recomp_insns[i];
            let is_b  = (recomp & 0xFC000000) == 0x14000000;
            let is_bl = (recomp & 0xFC000000) == 0x94000000;
            if is_b || is_bl {
                let imm26 = recomp & 0x03FFFFFF;
                let sext = ((imm26 as i32) << 6) >> 6;
                let target = (t.recomp_base as i64 + off as i64 + (sext as i64) * 4) as u64;
                output.push_str(&format!(
                    "  +0x{:03x} {:08x} {} 0x{:x}\n",
                    off, orig_insns[i], if is_bl { "BL" } else { "B " }, target
                ));
            } else {
                output.push_str(&format!(
                    "  +0x{:03x} {:08x} → {:08x}\n", off, orig_insns[i], recomp
                ));
            }
            changed += 1;
        }
    }
    output.push_str(&format!("changed: {}/1024\n", changed));
    Ok(output)
    // TempRecomp Drop 自动 munmap
}

/// 列出所有已重编译的页
pub fn list_pages() -> Vec<(usize, usize, usize)> {
    ensure_init();
    let guard = RECOMP_PAGES.lock().unwrap();
    match guard.as_ref() {
        Some(pages) => pages
            .iter()
            .map(|(&orig, p)| (orig, p.recomp_ptr as usize, p.tramp_used))
            .collect(),
        None => vec![],
    }
}
