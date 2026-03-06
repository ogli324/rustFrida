//! Module API — Frida-style linker integration + JS Module namespace
//!
//! Provides:
//! - Unrestricted linker API (namespace bypass via __dl___loader_dlopen/dlvsym)
//! - libart.so symbol resolution (libart_dlsym)
//! - Linker soinfo list traversal (enumerate_soinfo)
//! - JS API: Module.findExportByName, Module.findBaseAddress, Module.enumerateModules
//!
//! Reference: frida-gum/gum/backend-linux/gumandroid.c

use crate::context::JSContext;
use crate::ffi;
use crate::jsapi::console::output_message;
use crate::jsapi::ptr::create_native_pointer;
use crate::jsapi::util::{add_cfunction_to_object, is_addr_accessible};
use crate::value::JSValue;
use std::collections::{HashMap, HashSet};
use std::ffi::CString;

// ============================================================================
// ELF types
// ============================================================================

/// ELF64 header
#[repr(C)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    _e_machine: u16,
    _e_version: u32,
    _e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    _e_flags: u32,
    _e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    _e_shentsize: u16,
    e_shnum: u16,
    _e_shstrndx: u16,
}

/// ELF64 program header
#[repr(C)]
struct Elf64Phdr {
    p_type: u32,
    _p_flags: u32,
    _p_offset: u64,
    p_vaddr: u64,
    _p_paddr: u64,
    _p_filesz: u64,
    _p_memsz: u64,
    _p_align: u64,
}

/// ELF64 symbol table entry
#[repr(C)]
struct Elf64Sym {
    st_name: u32,
    _st_info: u8,
    _st_other: u8,
    _st_shndx: u16,
    st_value: u64,
    _st_size: u64,
}

/// ELF64 section header (for reading .symtab from file)
#[repr(C)]
struct Elf64Shdr {
    sh_name: u32,
    sh_type: u32,
    _sh_flags: u64,
    _sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    _sh_info: u32,
    _sh_addralign: u64,
    sh_entsize: u64,
}

const PT_LOAD: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;

// ============================================================================
// Unrestricted linker API — Frida-style namespace bypass
// Reference: frida-gum/gum/backend-linux/gumandroid.c
// ============================================================================

/// Cached unrestricted linker API function pointers.
struct UnrestrictedLinkerApi {
    /// __dl___loader_dlopen(filename, flags, caller_addr) -> handle
    dlopen: unsafe extern "C" fn(*const i8, i32, *const std::ffi::c_void) -> *mut std::ffi::c_void,
    /// __dl___loader_dlvsym(handle, symbol, version, caller_addr) -> addr
    dlsym: unsafe extern "C" fn(*mut std::ffi::c_void, *const i8, *const i8, *const std::ffi::c_void) -> *mut std::ffi::c_void,
    /// Trusted caller address (linker64 内部地址，dlopen_addr)
    trusted_caller: *const std::ffi::c_void,
    /// dl_mutex — __dl__ZL10g_dl_mutex
    dl_mutex: *mut libc::pthread_mutex_t,
    /// solist_get_head() — __dl__Z15solist_get_headv
    solist_get_head: Option<unsafe extern "C" fn() -> *mut std::ffi::c_void>,
    /// solist global variable (fallback) — __dl__ZL6solist
    solist: *mut *mut std::ffi::c_void,
    /// soinfo::get_realpath() — __dl__ZNK6soinfo12get_realpathEv
    soinfo_get_path: Option<unsafe extern "C" fn(*mut std::ffi::c_void) -> *const std::os::raw::c_char>,
}

unsafe impl Send for UnrestrictedLinkerApi {}
unsafe impl Sync for UnrestrictedLinkerApi {}

static UNRESTRICTED_LINKER_API: std::sync::OnceLock<Option<UnrestrictedLinkerApi>> = std::sync::OnceLock::new();

/// Newtype wrapper for *mut c_void to implement Send+Sync
pub(crate) struct SyncPtr(pub(crate) *mut std::ffi::c_void);
unsafe impl Send for SyncPtr {}
unsafe impl Sync for SyncPtr {}

static LIBART_HANDLE: std::sync::OnceLock<SyncPtr> = std::sync::OnceLock::new();

/// Cached libart.so address range (start, end).
pub(crate) static LIBART_RANGE: std::sync::OnceLock<(u64, u64)> = std::sync::OnceLock::new();

/// Cached libart.so full file path.
static LIBART_PATH: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

// ============================================================================
// /proc/self/maps parsing
// ============================================================================

/// Parse /proc/self/maps to find the libart.so address range and file path.
pub(crate) fn probe_libart_range() -> (u64, u64) {
    let maps = match super::util::read_proc_self_maps() {
        Some(s) => s,
        None => return (0, 0),
    };

    let mut range_start: u64 = u64::MAX;
    let mut range_end: u64 = 0;
    let mut found_path: Option<String> = None;

    for line in maps.lines() {
        if !line.contains("libart.so") {
            continue;
        }
        let addr_part = match line.split_whitespace().next() {
            Some(a) => a,
            None => continue,
        };
        let mut parts = addr_part.split('-');
        let start = parts.next().and_then(|s| u64::from_str_radix(s, 16).ok());
        let end = parts.next().and_then(|s| u64::from_str_radix(s, 16).ok());

        if let (Some(s), Some(e)) = (start, end) {
            if s < range_start { range_start = s; }
            if e > range_end { range_end = e; }
        }

        if found_path.is_none() {
            if let Some(path) = line.split_whitespace().last() {
                if path.contains("libart.so") {
                    found_path = Some(path.to_string());
                }
            }
        }
    }

    let _ = LIBART_PATH.set(found_path.clone());

    if range_start == u64::MAX {
        (0, 0)
    } else {
        output_message(&format!(
            "[module] libart.so range: {:#x}-{:#x}, path: {:?}",
            range_start, range_end, found_path
        ));
        (range_start, range_end)
    }
}

/// 通过 /proc/self/maps 获取指定模块的地址范围 (start, end)。
/// 返回 (0, 0) 表示未找到。
pub(crate) fn probe_module_range(module_name: &str) -> (u64, u64) {
    let maps = match super::util::read_proc_self_maps() {
        Some(s) => s,
        None => return (0, 0),
    };

    let mut range_start: u64 = u64::MAX;
    let mut range_end: u64 = 0;

    for line in maps.lines() {
        if !line.contains(module_name) {
            continue;
        }
        // Verify the path field actually contains the module name
        let path = match line.split_whitespace().last() {
            Some(p) if p.contains(module_name) => p,
            _ => continue,
        };
        let basename = path.rsplit('/').next().unwrap_or(path);
        if basename != module_name {
            continue;
        }

        let addr_part = match line.split_whitespace().next() {
            Some(a) => a,
            None => continue,
        };
        let mut parts = addr_part.split('-');
        let start = parts.next().and_then(|s| u64::from_str_radix(s, 16).ok());
        let end = parts.next().and_then(|s| u64::from_str_radix(s, 16).ok());

        if let (Some(s), Some(e)) = (start, end) {
            if s < range_start { range_start = s; }
            if e > range_end { range_end = e; }
        }
    }

    if range_start == u64::MAX {
        (0, 0)
    } else {
        (range_start, range_end)
    }
}

/// Parse /proc/self/maps to find a module's base address.
fn find_module_base(module_name: &str) -> u64 {
    let maps = match super::util::read_proc_self_maps() {
        Some(s) => s,
        None => return 0,
    };

    for line in maps.lines() {
        if !line.contains(module_name) {
            continue;
        }
        // Only match lines where the path field actually contains the module name
        let path = match line.split_whitespace().last() {
            Some(p) if p.contains(module_name) => p,
            _ => continue,
        };
        // Verify exact filename match (avoid "libfoo.so" matching "libfoo.so.1")
        let basename = path.rsplit('/').next().unwrap_or(path);
        if basename != module_name && !basename.starts_with(&format!("{}.", module_name)) {
            // Also check if module_name is a path suffix
            if !path.ends_with(module_name) {
                continue;
            }
        }

        let addr_part = match line.split_whitespace().next() {
            Some(a) => a,
            None => continue,
        };
        if let Some(start) = addr_part.split('-').next().and_then(|s| u64::from_str_radix(s, 16).ok()) {
            return start;
        }
    }
    0
}

/// Module info from /proc/self/maps
struct ModuleInfo {
    name: String,
    base: u64,
    size: u64,
    path: String,
}

/// Parse /proc/self/maps and aggregate VMAs per unique path.
fn enumerate_modules_from_maps() -> Vec<ModuleInfo> {
    let maps = match super::util::read_proc_self_maps() {
        Some(s) => s,
        None => return Vec::new(),
    };

    // Collect (path -> (min_start, max_end)) using insertion-order Vec
    let mut modules: Vec<(String, u64, u64)> = Vec::new();

    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let addr_part = match fields.next() {
            Some(a) => a,
            None => continue,
        };
        // Skip non-file mappings (no path field, or path starts with '[')
        // fields: perms, offset, dev, inode, path
        let _perms = fields.next();
        let _offset = fields.next();
        let _dev = fields.next();
        let _inode = fields.next();
        let path = match fields.next() {
            Some(p) if !p.starts_with('[') && p.contains('/') => p,
            _ => continue,
        };

        let mut parts = addr_part.split('-');
        let start = match parts.next().and_then(|s| u64::from_str_radix(s, 16).ok()) {
            Some(s) => s,
            None => continue,
        };
        let end = match parts.next().and_then(|s| u64::from_str_radix(s, 16).ok()) {
            Some(e) => e,
            None => continue,
        };

        // Find or insert
        if let Some(entry) = modules.iter_mut().find(|(p, _, _)| p == path) {
            if start < entry.1 { entry.1 = start; }
            if end > entry.2 { entry.2 = end; }
        } else {
            modules.push((path.to_string(), start, end));
        }
    }

    modules.into_iter().map(|(path, base, end)| {
        let name = path.rsplit('/').next().unwrap_or(&path).to_string();
        ModuleInfo {
            name,
            base,
            size: end - base,
            path,
        }
    }).collect()
}

// ============================================================================
// ELF symbol lookup — Frida-style (gum_elf_module)
//
// Strategy: file from disk first, memory at base_address as fallback.
// One read, one pass through .symtab, batch-extract all needed symbols.
//
// Reference: gumelfmodule.c — gum_elf_module_load_file_data():
//   1. g_mapped_file_new(path) → mmap from disk
//   2. If file not readable (ONLINE mode) → use base_address as data pointer
// ============================================================================

/// Batch lookup symbols from an ELF module's .symtab.
///
/// Strategy (Frida-style, gum_elf_module):
/// 1. Try read file from disk → parse .symtab in one pass
/// 2. If file not accessible → read from in-memory ELF mapping at base_address
///
/// Returns HashMap of found symbols: name -> runtime_address (load_bias applied).
unsafe fn elf_module_find_symbols(
    file_path: &str,
    base_address: u64,
    wanted: &[&str],
) -> HashMap<String, u64> {
    if wanted.is_empty() {
        return HashMap::new();
    }

    let wanted_set: HashSet<&str> = wanted.iter().copied().collect();
    let mut result = HashMap::new();

    // Compute load_bias from in-memory program headers
    let load_bias = elf_compute_load_bias(base_address);

    // Strategy 1: read file from disk (one read, one pass)
    if let Ok(data) = std::fs::read(file_path) {
        elf_find_symbols_in_data(&data, &wanted_set, load_bias, &mut result);
        if !result.is_empty() {
            return result;
        }
    }

    // Strategy 2: read from in-memory ELF at base_address (Frida fallback)
    output_message(&format!(
        "[module] file read failed for {}, trying memory at {:#x}",
        file_path, base_address
    ));
    elf_find_symbols_in_memory(base_address, &wanted_set, load_bias, &mut result);

    result
}

/// Compute load_bias from in-memory ELF at base_address.
/// load_bias = base_address - first_PT_LOAD.p_vaddr
unsafe fn elf_compute_load_bias(base_address: u64) -> u64 {
    if base_address == 0 {
        return 0;
    }
    let ehdr = &*(base_address as *const Elf64Ehdr);
    if ehdr.e_ident[0..4] != *b"\x7fELF" || ehdr.e_ident[4] != 2 {
        return base_address;
    }
    let phdr_base = base_address + ehdr.e_phoff;
    for i in 0..ehdr.e_phnum as u64 {
        let phdr = &*((phdr_base + i * ehdr.e_phentsize as u64) as *const Elf64Phdr);
        if phdr.p_type == PT_LOAD {
            return base_address.wrapping_sub(phdr.p_vaddr);
        }
    }
    base_address
}

/// Find symbols in .symtab from file data (byte slice). One pass.
fn elf_find_symbols_in_data(
    data: &[u8],
    wanted: &HashSet<&str>,
    load_bias: u64,
    result: &mut HashMap<String, u64>,
) {
    if data.len() < std::mem::size_of::<Elf64Ehdr>() {
        return;
    }

    unsafe {
        let ehdr = &*(data.as_ptr() as *const Elf64Ehdr);
        if ehdr.e_ident[0..4] != *b"\x7fELF" || ehdr.e_ident[4] != 2 {
            return;
        }

        let shdr_off = ehdr.e_shoff as usize;
        let shdr_size = std::mem::size_of::<Elf64Shdr>();
        let shnum = ehdr.e_shnum as usize;

        if shdr_off == 0 || shdr_off + shnum * shdr_size > data.len() {
            return;
        }

        // Find SHT_SYMTAB
        let mut symtab_shdr: Option<&Elf64Shdr> = None;
        for i in 0..shnum {
            let shdr = &*(data.as_ptr().add(shdr_off + i * shdr_size) as *const Elf64Shdr);
            if shdr.sh_type == SHT_SYMTAB {
                symtab_shdr = Some(shdr);
                break;
            }
        }

        let symtab = match symtab_shdr {
            Some(s) => s,
            None => return,
        };

        let strtab_idx = symtab.sh_link as usize;
        if strtab_idx >= shnum {
            return;
        }
        let strtab_shdr = &*(data.as_ptr().add(shdr_off + strtab_idx * shdr_size) as *const Elf64Shdr);
        if strtab_shdr.sh_type != SHT_STRTAB {
            return;
        }

        let strtab_off = strtab_shdr.sh_offset as usize;
        let strtab_size = strtab_shdr.sh_size as usize;
        if strtab_off + strtab_size > data.len() {
            return;
        }

        let symtab_off = symtab.sh_offset as usize;
        let sym_size = if symtab.sh_entsize > 0 {
            symtab.sh_entsize as usize
        } else {
            std::mem::size_of::<Elf64Sym>()
        };
        let nsyms = symtab.sh_size as usize / sym_size;

        if symtab_off + nsyms * sym_size > data.len() {
            return;
        }

        let mut remaining = wanted.len();

        for idx in 0..nsyms {
            if remaining == 0 {
                break;
            }

            let sym = &*(data.as_ptr().add(symtab_off + idx * sym_size) as *const Elf64Sym);
            if sym.st_name == 0 || sym.st_value == 0 {
                continue;
            }

            let name_off = strtab_off + sym.st_name as usize;
            if name_off >= strtab_off + strtab_size {
                continue;
            }

            // Read null-terminated name
            let name_slice = &data[name_off..strtab_off + strtab_size];
            let name_len = name_slice.iter().position(|&b| b == 0).unwrap_or(0);
            if name_len == 0 {
                continue;
            }

            if let Ok(name) = std::str::from_utf8(&name_slice[..name_len]) {
                if wanted.contains(name) && !result.contains_key(name) {
                    result.insert(name.to_string(), load_bias + sym.st_value);
                    remaining -= 1;
                }
            }
        }
    }
}

/// Find symbols in .symtab from in-memory ELF at base_address.
///
/// Fallback when file is not readable on disk.
/// Uses mincore(2) to check page accessibility before each read.
///
/// Reference: gumelfmodule.c line 570-572 — ONLINE mode fallback:
///   self->file_bytes = g_bytes_new_static(base_address, G_MAXSIZE - base_address)
unsafe fn elf_find_symbols_in_memory(
    base_address: u64,
    wanted: &HashSet<&str>,
    load_bias: u64,
    result: &mut HashMap<String, u64>,
) {
    if base_address == 0 {
        return;
    }

    // Check ELF header accessible
    if !is_addr_accessible(base_address, std::mem::size_of::<Elf64Ehdr>()) {
        return;
    }

    let ehdr = &*(base_address as *const Elf64Ehdr);
    if ehdr.e_ident[0..4] != *b"\x7fELF" || ehdr.e_ident[4] != 2 {
        return;
    }

    let shdr_size = std::mem::size_of::<Elf64Shdr>();
    let shnum = ehdr.e_shnum as usize;
    let shdr_addr = base_address + ehdr.e_shoff;

    // Check section headers accessible
    if !is_addr_accessible(shdr_addr, shnum * shdr_size) {
        output_message("[module] section headers not accessible in memory");
        return;
    }

    // Find SHT_SYMTAB
    let mut symtab_shdr: Option<Elf64ShdrCopy> = None;
    for i in 0..shnum {
        let shdr = &*((shdr_addr as usize + i * shdr_size) as *const Elf64Shdr);
        if shdr.sh_type == SHT_SYMTAB {
            symtab_shdr = Some(Elf64ShdrCopy {
                sh_offset: shdr.sh_offset,
                sh_size: shdr.sh_size,
                sh_link: shdr.sh_link,
                sh_entsize: shdr.sh_entsize,
            });
            break;
        }
    }

    let symtab = match symtab_shdr {
        Some(s) => s,
        None => {
            output_message("[module] .symtab not found in memory ELF");
            return;
        }
    };

    let strtab_idx = symtab.sh_link as usize;
    if strtab_idx >= shnum {
        return;
    }
    let strtab_shdr = &*((shdr_addr as usize + strtab_idx * shdr_size) as *const Elf64Shdr);
    if strtab_shdr.sh_type != SHT_STRTAB {
        return;
    }

    // Check .symtab and .strtab data accessible
    let symtab_data_addr = base_address + symtab.sh_offset;
    let strtab_data_addr = base_address + strtab_shdr.sh_offset;

    let sym_size = if symtab.sh_entsize > 0 {
        symtab.sh_entsize as usize
    } else {
        std::mem::size_of::<Elf64Sym>()
    };
    let nsyms = symtab.sh_size as usize / sym_size;
    let strtab_size = strtab_shdr.sh_size as usize;

    if !is_addr_accessible(symtab_data_addr, nsyms * sym_size) {
        output_message("[module] .symtab data not accessible in memory");
        return;
    }
    if !is_addr_accessible(strtab_data_addr, strtab_size) {
        output_message("[module] .strtab data not accessible in memory");
        return;
    }

    output_message(&format!(
        "[module] reading .symtab from memory: {} symbols", nsyms
    ));

    let mut remaining = wanted.len();

    for idx in 0..nsyms {
        if remaining == 0 {
            break;
        }

        let sym = &*((symtab_data_addr as usize + idx * sym_size) as *const Elf64Sym);
        if sym.st_name == 0 || sym.st_value == 0 {
            continue;
        }

        let name_off = sym.st_name as usize;
        if name_off >= strtab_size {
            continue;
        }

        let name_ptr = (strtab_data_addr as usize + name_off) as *const u8;
        let max_len = strtab_size - name_off;
        let name_slice = std::slice::from_raw_parts(name_ptr, max_len);
        let name_len = name_slice.iter().position(|&b| b == 0).unwrap_or(0);
        if name_len == 0 {
            continue;
        }

        if let Ok(name) = std::str::from_utf8(&name_slice[..name_len]) {
            if wanted.contains(name) && !result.contains_key(name) {
                result.insert(name.to_string(), load_bias + sym.st_value);
                remaining -= 1;
            }
        }
    }
}

/// Minimal copy of Elf64Shdr fields needed for .symtab processing.
/// Avoids holding a reference into memory that might be invalidated.
struct Elf64ShdrCopy {
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_entsize: u64,
}

// ============================================================================
// Linker info + init
// ============================================================================

/// Find linker64 base address and file path from /proc/self/maps.
fn find_linker_info() -> (u64, String) {
    let maps = match super::util::read_proc_self_maps() {
        Some(s) => s,
        None => return (0, String::new()),
    };

    for line in maps.lines() {
        if !line.contains("linker64") || line.contains(".so") {
            continue;
        }
        let addr_part = match line.split_whitespace().next() {
            Some(a) => a,
            None => continue,
        };
        let path = match line.split_whitespace().last() {
            Some(p) if p.contains("linker64") => p.to_string(),
            _ => continue,
        };
        let start = addr_part.split('-').next()
            .and_then(|s| u64::from_str_radix(s, 16).ok());
        if let Some(s) = start {
            return (s, path);
        }
    }
    (0, String::new())
}

/// Initialize the unrestricted linker API (Frida-style).
///
/// One read, one pass through .symtab — batch-extract all needed linker symbols.
/// Falls back to reading from in-memory ELF if file not readable.
///
/// Reference: gum_linker_api_try_init() in gumandroid.c:1127
unsafe fn init_unrestricted_linker_api() -> Option<UnrestrictedLinkerApi> {
    let (linker_base, linker_path) = find_linker_info();
    if linker_base == 0 || linker_path.is_empty() {
        output_message("[linker api] linker64 not found in /proc/self/maps");
        return None;
    }

    output_message(&format!(
        "[linker api] linker64 base={:#x}, path={}", linker_base, linker_path
    ));

    // Batch lookup all needed symbols in one pass (Frida-style)
    let symbols = elf_module_find_symbols(&linker_path, linker_base, &[
        // dlopen/dlvsym (API 28+)
        "__dl___loader_dlopen",
        "__dl___loader_dlvsym",
        // dlopen/dlvsym (API 26-27 fallback)
        "__dl__Z8__dlopenPKciPKv",
        "__dl__Z8__dlvsymPvPKcS1_PKv",
        // Linker internals (Frida's gum_store_linker_symbol_if_needed)
        "__dl__ZL10g_dl_mutex",
        "__dl__ZL8gDlMutex",                    // < API 21
        "__dl__Z15solist_get_headv",
        "__dl__ZL6solist",
        "__dl__ZNK6soinfo12get_realpathEv",
        "__dl__ZNK6soinfo7get_pathEv",           // older fallback
    ]);

    output_message(&format!("[linker api] found {} symbols in one pass", symbols.len()));
    for (name, addr) in &symbols {
        output_message(&format!("[linker api]   {}={:#x}", name, addr));
    }

    // Extract dlopen: prefer API 28+ name, fallback to API 26-27
    let dlopen_addr = symbols.get("__dl___loader_dlopen")
        .or_else(|| symbols.get("__dl__Z8__dlopenPKciPKv"))
        .copied();
    let dlsym_addr = symbols.get("__dl___loader_dlvsym")
        .or_else(|| symbols.get("__dl__Z8__dlvsymPvPKcS1_PKv"))
        .copied();

    if dlopen_addr.is_none() || dlsym_addr.is_none() {
        output_message(&format!(
            "[linker api] dlopen/dlsym not found: dlopen={:?}, dlsym={:?}",
            dlopen_addr, dlsym_addr
        ));
        return None;
    }

    let dlopen_addr = dlopen_addr.unwrap();
    let dlsym_addr = dlsym_addr.unwrap();

    // 使用已解析的 linker 符号地址作为 trusted_caller（避免 dlsym 依赖）
    // hide_soinfo.c 的 .init_array 会在 dlopen 时摘除 agent 的 soinfo，
    // 导致后续 dlsym(RTLD_DEFAULT, ...) 因找不到 caller 的 soinfo 而失败。
    // 直接用 linker64 内部地址作为 trusted_caller 绕过此问题。
    let trusted_caller = dlopen_addr as *mut std::ffi::c_void;

    output_message(&format!(
        "[linker api] unrestricted API: dlopen={:#x}, dlsym={:#x}, trusted_caller={:#x}",
        dlopen_addr, dlsym_addr, trusted_caller as u64
    ));

    // Extract optional linker internals
    let dl_mutex = symbols.get("__dl__ZL10g_dl_mutex")
        .or_else(|| symbols.get("__dl__ZL8gDlMutex"))
        .map(|&addr| addr as *mut libc::pthread_mutex_t)
        .unwrap_or_else(|| {
            output_message("[linker api] dl_mutex not found");
            std::ptr::null_mut()
        });

    let solist_get_head: Option<unsafe extern "C" fn() -> *mut std::ffi::c_void> =
        symbols.get("__dl__Z15solist_get_headv")
            .map(|&addr| std::mem::transmute(addr));

    let solist = symbols.get("__dl__ZL6solist")
        .map(|&addr| addr as *mut *mut std::ffi::c_void)
        .unwrap_or(std::ptr::null_mut());

    let soinfo_get_path: Option<unsafe extern "C" fn(*mut std::ffi::c_void) -> *const std::os::raw::c_char> =
        symbols.get("__dl__ZNK6soinfo12get_realpathEv")
            .or_else(|| symbols.get("__dl__ZNK6soinfo7get_pathEv"))
            .map(|&addr| std::mem::transmute(addr));
    if soinfo_get_path.is_none() {
        output_message("[linker api] soinfo_get_path not found");
    }

    Some(UnrestrictedLinkerApi {
        dlopen: std::mem::transmute(dlopen_addr),
        dlsym: std::mem::transmute(dlsym_addr),
        trusted_caller: trusted_caller as *const std::ffi::c_void,
        dl_mutex,
        solist_get_head,
        solist,
        soinfo_get_path,
    })
}

// ============================================================================
// Module handle + symbol resolution
// ============================================================================

/// Get a dlopen handle to libart.so via unrestricted linker API (Frida-style).
unsafe fn get_libart_handle() -> *mut std::ffi::c_void {
    LIBART_HANDLE.get_or_init(|| {
        let api = UNRESTRICTED_LINKER_API.get_or_init(|| init_unrestricted_linker_api());
        if let Some(api) = api {
            let &(libart_base, _) = LIBART_RANGE.get_or_init(probe_libart_range);
            if libart_base == 0 {
                output_message("[linker api] libart.so base not found in /proc/self/maps");
                return SyncPtr(std::ptr::null_mut());
            }

            let caller_addr = libart_base as *const std::ffi::c_void;

            let paths_to_try: Vec<String> = {
                let mut paths = Vec::new();
                if let Some(Some(path)) = LIBART_PATH.get() {
                    paths.push(path.clone());
                }
                paths.push("libart.so".to_string());
                paths
            };

            for path in &paths_to_try {
                let c_path = CString::new(path.as_str()).unwrap();
                let handle = (api.dlopen)(
                    c_path.as_ptr() as *const i8,
                    libc::RTLD_NOW | libc::RTLD_NOLOAD,
                    caller_addr,
                );
                if !handle.is_null() {
                    output_message(&format!(
                        "[linker api] dlopen({}, NOLOAD, caller={:#x}) = {:?}",
                        path, libart_base, handle
                    ));
                    return SyncPtr(handle);
                }

                let err = libc::dlerror();
                if !err.is_null() {
                    let err_msg = std::ffi::CStr::from_ptr(err).to_string_lossy();
                    output_message(&format!(
                        "[linker api] dlopen({}, NOLOAD) failed: {}", path, err_msg
                    ));
                }
            }

            output_message("[linker api] all dlopen attempts failed");
        }
        SyncPtr(std::ptr::null_mut())
    }).0
}

/// Get a dlopen handle to an arbitrary module via unrestricted linker API.
///
/// hide_soinfo 摘除 agent soinfo 后，libc::dlopen 会导致 linker 内部空指针崩溃，
/// 因此跳过 standard dlopen fast path，直接走 unrestricted API。
unsafe fn module_dlopen(module_name: &str) -> *mut std::ffi::c_void {
    let c_name = CString::new(module_name).unwrap();

    // 直接走 unrestricted path（跳过 standard dlopen fast path）
    let api = UNRESTRICTED_LINKER_API.get_or_init(|| init_unrestricted_linker_api());
    if let Some(api) = api {
        let base = find_module_base(module_name);
        if base != 0 {
            let caller_addr = base as *const std::ffi::c_void;
            let handle = (api.dlopen)(
                c_name.as_ptr() as *const i8,
                libc::RTLD_NOW | libc::RTLD_NOLOAD,
                caller_addr,
            );
            if !handle.is_null() {
                return handle;
            }
        }

        // Try with trusted_caller as fallback
        let handle = (api.dlopen)(
            c_name.as_ptr() as *const i8,
            libc::RTLD_NOW | libc::RTLD_NOLOAD,
            api.trusted_caller,
        );
        if !handle.is_null() {
            return handle;
        }
    }

    std::ptr::null_mut()
}

/// Resolve a symbol from an arbitrary module, bypassing linker namespace restrictions.
///
/// hide_soinfo 摘除 agent soinfo 后，libc::dlsym(RTLD_DEFAULT) 可能导致 linker
/// 内部空指针崩溃（caller soinfo 不存在），因此跳过 fast path，直接走 unrestricted API。
pub(crate) unsafe fn module_dlsym(module_name: &str, symbol: &str) -> *mut std::ffi::c_void {
    let c_sym = CString::new(symbol).unwrap();

    // Unrestricted path (skip RTLD_DEFAULT fast path — crashes after soinfo removal)
    let api = UNRESTRICTED_LINKER_API.get_or_init(|| init_unrestricted_linker_api());
    if let Some(api) = api {
        let handle = module_dlopen(module_name);
        if !handle.is_null() {
            let addr = (api.dlsym)(handle, c_sym.as_ptr() as *const i8, std::ptr::null(), api.trusted_caller);
            if !addr.is_null() {
                return addr;
            }
        }
    }

    std::ptr::null_mut()
}

/// Resolve a symbol from libart.so, bypassing linker namespace restrictions.
///
/// hide_soinfo 摘除 agent soinfo 后，libc::dlsym(RTLD_DEFAULT) 会导致 linker
/// 内部空指针崩溃，因此跳过 fast path，直接走 unrestricted dlvsym。
pub(crate) unsafe fn libart_dlsym(name: &str) -> *mut std::ffi::c_void {
    let c_sym = CString::new(name).unwrap();

    // 直接走 unrestricted dlvsym（跳过 RTLD_DEFAULT fast path）
    let api = UNRESTRICTED_LINKER_API.get_or_init(|| init_unrestricted_linker_api());
    if let Some(api) = api {
        let handle = get_libart_handle();
        if !handle.is_null() {
            let addr = (api.dlsym)(handle, c_sym.as_ptr() as *const i8, std::ptr::null(), api.trusted_caller);
            if !addr.is_null() {
                return addr;
            }
        }
    }

    std::ptr::null_mut()
}

/// 在多个候选符号中查找第一个可用的（通过 libart_dlsym）
pub(crate) unsafe fn dlsym_first_match(candidates: &[&str]) -> u64 {
    for &sym_name in candidates {
        let addr = libart_dlsym(sym_name);
        if !addr.is_null() {
            return addr as u64;
        }
    }
    0
}

/// Check if an address falls within libart.so.
pub(crate) fn is_in_libart(addr: u64) -> bool {
    if addr == 0 {
        return false;
    }
    let &(start, end) = LIBART_RANGE.get_or_init(probe_libart_range);
    if start == 0 && end == 0 {
        unsafe {
            let mut info: libc::Dl_info = std::mem::zeroed();
            if libc::dladdr(addr as *const std::ffi::c_void, &mut info) != 0 {
                if !info.dli_fname.is_null() {
                    let name = std::ffi::CStr::from_ptr(info.dli_fname).to_bytes();
                    return name.windows(9).any(|w| w == b"libart.so");
                }
            }
            false
        }
    } else {
        addr >= start && addr < end
    }
}

// ============================================================================
// soinfo traversal (Frida-style)
// ============================================================================

/// Walk the linker's soinfo linked list under dl_mutex.
/// Returns Vec<(base_addr, path)> for all loaded modules.
///
/// Reference: gum_enumerate_soinfo() at gumandroid.c:994
///
/// soinfo layout (API 26+):
///   soinfo starts with a ListEntry (prev, next) = 16 bytes
///   body = soinfo + 16 (API 26+) or soinfo + 12 (API 23-25)
///   body->next at body + 0x28 (40 bytes)
///   body->base at body + 0x80 (128 bytes, after phdr/phnum/entry/base)
#[allow(dead_code)]
unsafe fn enumerate_soinfo() -> Vec<(u64, String)> {
    let api = match UNRESTRICTED_LINKER_API.get_or_init(|| init_unrestricted_linker_api()) {
        Some(api) => api,
        None => return Vec::new(),
    };

    // Get soinfo list head
    let head: *mut std::ffi::c_void = if let Some(get_head) = api.solist_get_head {
        get_head()
    } else if !api.solist.is_null() {
        *api.solist
    } else {
        return Vec::new();
    };

    if head.is_null() {
        return Vec::new();
    }

    let soinfo_get_path = match api.soinfo_get_path {
        Some(f) => f,
        None => return Vec::new(),
    };

    let mut result = Vec::new();

    // Lock dl_mutex for thread safety
    let has_mutex = !api.dl_mutex.is_null();
    if has_mutex {
        libc::pthread_mutex_lock(api.dl_mutex);
    }

    let mut current = head;
    let mut count = 0u32;
    while !current.is_null() && count < 4096 {
        count += 1;

        // Get path via soinfo::get_realpath()
        let path_ptr = soinfo_get_path(current);
        let path = if !path_ptr.is_null() {
            std::ffi::CStr::from_ptr(path_ptr).to_string_lossy().to_string()
        } else {
            String::new()
        };

        // soinfo body: skip ListEntry header (16 bytes on API 26+)
        // body->base is at a known offset — but varies by Android version.
        // For the JS API we use /proc/self/maps instead (more reliable).
        // Here we just collect paths for namespace-aware dlopen.
        let base = find_module_base_for_path(&path);
        if base != 0 || !path.is_empty() {
            result.push((base, path));
        }

        // next soinfo: soinfo is a linked list via ListEntry at offset 0
        // ListEntry { next: *mut soinfo, prev: *mut soinfo }
        // next is at offset 0
        let next = *(current as *const *mut std::ffi::c_void);
        current = next;
    }

    if has_mutex {
        libc::pthread_mutex_unlock(api.dl_mutex);
    }

    result
}

/// Find base address for a given full path from /proc/self/maps.
fn find_module_base_for_path(path: &str) -> u64 {
    if path.is_empty() {
        return 0;
    }
    let maps = match super::util::read_proc_self_maps() {
        Some(s) => s,
        None => return 0,
    };
    for line in maps.lines() {
        if !line.contains(path) {
            continue;
        }
        let file_path = match line.split_whitespace().last() {
            Some(p) if p == path => p,
            _ => continue,
        };
        let _ = file_path; // used for exact match above
        let addr_part = match line.split_whitespace().next() {
            Some(a) => a,
            None => continue,
        };
        if let Some(start) = addr_part.split('-').next().and_then(|s| u64::from_str_radix(s, 16).ok()) {
            return start;
        }
    }
    0
}

// ============================================================================
// JS API: Module namespace
// ============================================================================

/// Module.findExportByName(moduleName, symbolName) → NativePointer | null
///
/// moduleName == null → dlsym(RTLD_DEFAULT, symbolName)
/// moduleName != null → module_dlsym(moduleName, symbolName)
unsafe extern "C" fn js_module_find_export(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Module.findExportByName(moduleName, symbolName) requires 2 arguments\0".as_ptr() as *const _,
        );
    }

    let arg0 = JSValue(*argv);
    let arg1 = JSValue(*argv.add(1));

    // Get symbol name (required)
    let symbol_name = match arg1.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"symbolName must be a string\0".as_ptr() as *const _,
            );
        }
    };

    let addr: *mut std::ffi::c_void = if arg0.is_null() || arg0.is_undefined() {
        // null module → search all loaded modules (跳过 RTLD_DEFAULT，soinfo 摘除后会崩溃)
        let c_sym = CString::new(symbol_name.as_str()).unwrap();
        let api = UNRESTRICTED_LINKER_API.get_or_init(|| init_unrestricted_linker_api());
        if let Some(api) = api {
            (api.dlsym)(libc::RTLD_DEFAULT as _, c_sym.as_ptr() as *const i8, std::ptr::null(), api.trusted_caller)
        } else {
            std::ptr::null_mut()
        }
    } else {
        // Specific module
        let module_name = match arg0.to_string(ctx) {
            Some(s) => s,
            None => {
                return ffi::JS_ThrowTypeError(
                    ctx,
                    b"moduleName must be a string or null\0".as_ptr() as *const _,
                );
            }
        };
        module_dlsym(&module_name, &symbol_name)
    };

    if addr.is_null() {
        JSValue::null().raw()
    } else {
        create_native_pointer(ctx, addr as u64).raw()
    }
}

/// Module.findBaseAddress(moduleName) → NativePointer | null
unsafe extern "C" fn js_module_find_base(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Module.findBaseAddress(moduleName) requires 1 argument\0".as_ptr() as *const _,
        );
    }

    let arg0 = JSValue(*argv);
    let module_name = match arg0.to_string(ctx) {
        Some(s) => s,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"moduleName must be a string\0".as_ptr() as *const _,
            );
        }
    };

    let base = find_module_base(&module_name);
    if base == 0 {
        JSValue::null().raw()
    } else {
        create_native_pointer(ctx, base).raw()
    }
}

/// Module.enumerateModules() → Array of {name, base, size, path}
unsafe extern "C" fn js_module_enumerate(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let modules = enumerate_modules_from_maps();

    let arr = ffi::JS_NewArray(ctx);
    for (i, m) in modules.iter().enumerate() {
        let obj = ffi::JS_NewObject(ctx);
        let obj_val = JSValue(obj);

        let name_val = JSValue::string(ctx, &m.name);
        let base_val = create_native_pointer(ctx, m.base);
        let size_val = JSValue(ffi::JS_NewBigUint64(ctx, m.size));
        let path_val = JSValue::string(ctx, &m.path);

        obj_val.set_property(ctx, "name", name_val);
        obj_val.set_property(ctx, "base", base_val);
        obj_val.set_property(ctx, "size", size_val);
        obj_val.set_property(ctx, "path", path_val);

        ffi::JS_SetPropertyUint32(ctx, arr, i as u32, obj);
    }

    arr
}

/// Register Module JS API
pub fn register_module_api(ctx: &JSContext) {
    let global = ctx.global_object();

    unsafe {
        let ctx_ptr = ctx.as_ptr();
        let module_obj = ffi::JS_NewObject(ctx_ptr);

        add_cfunction_to_object(ctx_ptr, module_obj, "findExportByName", js_module_find_export, 2);
        add_cfunction_to_object(ctx_ptr, module_obj, "findBaseAddress", js_module_find_base, 1);
        add_cfunction_to_object(ctx_ptr, module_obj, "enumerateModules", js_module_enumerate, 0);

        global.set_property(ctx.as_ptr(), "Module", JSValue(module_obj));
    }

    global.free(ctx.as_ptr());
}
