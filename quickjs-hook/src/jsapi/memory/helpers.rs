//! Memory helper functions

use crate::ffi;
use crate::jsapi::ptr::get_native_pointer_addr;
use crate::value::JSValue;

/// Helper to get address from argument
pub(super) unsafe fn get_addr_from_arg(ctx: *mut ffi::JSContext, val: JSValue) -> Option<u64> {
    get_native_pointer_addr(ctx, val).or_else(|| val.to_u64(ctx))
}

/// Parse page permissions for `addr` from /proc/self/maps.
/// Returns the libc PROT_* flags for the page, or `None` if not found.
fn get_page_prot(addr: u64) -> Option<i32> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let file = File::open("/proc/self/maps").ok()?;
    for line in BufReader::new(file).lines().flatten() {
        // Format: "start-end perms offset dev inode pathname"
        let b = line.as_bytes();
        if let Some(dash) = b.iter().position(|&x| x == b'-') {
            let Ok(start) = u64::from_str_radix(&line[..dash], 16) else {
                continue;
            };
            let rest = &line[dash + 1..];
            if let Some(sp) = rest.bytes().position(|x| x == b' ') {
                let Ok(end) = u64::from_str_radix(&rest[..sp], 16) else {
                    continue;
                };
                if addr >= start && addr < end {
                    let perms = rest[sp + 1..].as_bytes();
                    if perms.len() < 3 {
                        return None;
                    }
                    let mut prot = 0i32;
                    if perms[0] == b'r' {
                        prot |= libc::PROT_READ;
                    }
                    if perms[1] == b'w' {
                        prot |= libc::PROT_WRITE;
                    }
                    if perms[2] == b'x' {
                        prot |= libc::PROT_EXEC;
                    }
                    return Some(prot);
                }
            }
        }
    }
    None
}

/// Check whether the page containing `addr` is writable by parsing /proc/self/maps.
/// Returns `true` if writable (or if the map cannot be read — assume writable to avoid
/// breaking writes to legitimate RW pages).
#[allow(dead_code)]
pub(super) fn is_page_writable(addr: u64) -> bool {
    match get_page_prot(addr) {
        Some(prot) => (prot & libc::PROT_WRITE) != 0,
        None => true, // can't determine; assume writable
    }
}

/// Perform `write_fn` at `addr`, temporarily making the containing page(s) writable
/// if they are currently mapped R-X (e.g. code pages).
///
/// Returns `true` on success, `false` if mprotect fails.
pub(super) unsafe fn write_with_perm(addr: u64, size: usize, write_fn: impl FnOnce()) -> bool {
    let orig_prot = get_page_prot(addr);
    if orig_prot.map_or(true, |p| (p & libc::PROT_WRITE) != 0) {
        // Already writable (or can't determine)
        write_fn();
        return true;
    }
    let orig_prot = orig_prot.unwrap(); // safe: we checked Some above
                                        // Page is not writable. Temporarily add PROT_WRITE.
    const PAGE_SIZE: usize = 0x1000;
    let start_page = (addr as usize) & !(PAGE_SIZE - 1);
    // 计算写入是否跨页，只对需要的页进行 mprotect
    let end_page = ((addr as usize) + size - 1) & !(PAGE_SIZE - 1);
    let mprotect_len = if start_page == end_page {
        PAGE_SIZE
    } else {
        PAGE_SIZE * 2
    };
    if libc::mprotect(
        start_page as *mut libc::c_void,
        mprotect_len,
        orig_prot | libc::PROT_WRITE,
    ) != 0
    {
        return false;
    }
    write_fn();
    // 恢复原始权限，检查返回值
    if libc::mprotect(start_page as *mut libc::c_void, mprotect_len, orig_prot) != 0 {
        crate::jsapi::console::output_message(&format!(
            "[warn] mprotect 恢复权限失败: addr=0x{:x}, len=0x{:x}",
            start_page, mprotect_len
        ));
    }
    true
}
