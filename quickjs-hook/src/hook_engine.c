/*
 * hook_engine.c - ARM64 Inline Hook Engine — Core
 *
 * Global state, logging, initialization, find_hook, cleanup.
 * Implementation details are split across:
 *   hook_engine_mem.c    — memory pool, alloc, wxshadow, relocate
 *   hook_engine_inline.c — inline hook install/attach/replace/remove
 *   hook_engine_redir.c  — redirect and native thunks
 *   hook_engine_art.c    — ART method router
 */

#include "hook_engine_internal.h"

/* Global engine state */
HookEngine g_engine = {0};

/* --- Diagnostic log infrastructure --- */

HookLogFn g_log_fn = NULL;

void hook_engine_set_log_fn(HookLogFn fn) {
    g_log_fn = fn;
}

void hook_log(const char* fmt, ...) {
    if (!g_log_fn) return;
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    g_log_fn(buf);
}

/* Initialize the hook engine */
int hook_engine_init(void* exec_mem, size_t size) {
    if (g_engine.initialized) {
        return 0; /* Already initialized */
    }

    if (!exec_mem || size < 4096) {
        return -1;
    }

    g_engine.exec_mem = exec_mem;
    g_engine.exec_mem_size = size;
    g_engine.exec_mem_used = 0;
    g_engine.hooks = NULL;
    g_engine.free_list = NULL;
    g_engine.redirects = NULL;
    g_engine.exec_mem_page_size = (size_t)sysconf(_SC_PAGESIZE);
    pthread_mutex_init(&g_engine.lock, NULL);
    g_engine.initialized = 1;

    return 0;
}

/* Find hook entry by target address */
HookEntry* find_hook(void* target) {
    HookEntry* entry = g_engine.hooks;
    while (entry) {
        if (entry->target == target) return entry;
        entry = entry->next;
    }
    return NULL;
}

void hook_engine_begin_bulk_cleanup(void) {
    g_engine.bulk_cleanup = 1;
}

/* Batch unhook helpers */

void batch_add_dirty_page(uintptr_t page) {
    for (int i = 0; i < g_engine.batch_dirty_count; i++) {
        if (g_engine.batch_dirty_pages[i] == page) return; /* dedup */
    }
    if (g_engine.batch_dirty_count < BATCH_DIRTY_PAGES_MAX) {
        g_engine.batch_dirty_pages[g_engine.batch_dirty_count++] = page;
    } else {
        hook_log("batch_add_dirty_page: overflow, page %p dropped", (void*)page);
    }
}

void hook_begin_batch(void) {
    g_engine.batch_mode = 1;
    g_engine.batch_dirty_count = 0;
}

void hook_end_batch(void) {
    if (!g_engine.batch_mode) return;
    g_engine.batch_mode = 0;

    if (g_engine.batch_dirty_count == 0) return;

    pthread_mutex_lock(&g_engine.lock);

    /* Release each dirty page once */
    for (int i = 0; i < g_engine.batch_dirty_count; i++) {
        uintptr_t page = g_engine.batch_dirty_pages[i];
        int ret = prctl(PR_WXSHADOW_RELEASE, 0, page, 0, 0);
        if (ret != 0) {
            ret = prctl(PR_WXSHADOW_RELEASE, getpid(), page, 0, 0);
        }
        if (ret != 0) {
            hook_log("hook_end_batch: wxshadow_release page %p failed (errno=%d)", (void*)page, errno);
        }
    }

    /* Re-patch surviving stealth hooks on dirty pages */
    for (HookEntry* entry = g_engine.hooks; entry; entry = entry->next) {
        if (!entry->stealth) continue;
        uintptr_t entry_page = (uintptr_t)entry->target & ~0xFFFUL;
        for (int i = 0; i < g_engine.batch_dirty_count; i++) {
            if (g_engine.batch_dirty_pages[i] == entry_page) {
                uint8_t jump_buf[MIN_HOOK_SIZE];
                void* jump_dest = entry->thunk ? entry->thunk : entry->replacement;
                int jlen = hook_write_jump(jump_buf, jump_dest);
                if (jlen > 0) {
                    wxshadow_patch(entry->target, jump_buf, jlen);
                }
                break;
            }
        }
    }

    g_engine.batch_dirty_count = 0;
    pthread_mutex_unlock(&g_engine.lock);
}

/* Cleanup all hooks */
void hook_engine_cleanup(void) {
    if (!g_engine.initialized) return;

    pthread_mutex_lock(&g_engine.lock);

    /* Count hooks on both lists for diagnostics */
    int hooks_count = 0, free_count = 0, stealth_hooks = 0, stealth_free = 0;
    for (HookEntry* e = g_engine.hooks; e; e = e->next) {
        hooks_count++;
        if (e->stealth) stealth_hooks++;
    }
    for (HookEntry* e = g_engine.free_list; e; e = e->next) {
        free_count++;
        if (e->stealth) stealth_free++;
    }
    hook_log("hook_engine_cleanup: hooks=%d (stealth=%d), free_list=%d (stealth=%d)",
             hooks_count, stealth_hooks, free_count, stealth_free);

    /* Release all wxshadow pages at once (addr=0 → teardown all shadows in this mm).
     * This is the ONLY way to remove stealth hooks — the shadow page is a
     * kernel-level instruction-view overlay; mprotect+memcpy writes to the
     * data view and cannot affect the shadow. */
    int wx_ret = wxshadow_release_all();
    hook_log("hook_engine_cleanup: wxshadow_release_all returned %d", wx_ret);

    /* Restore non-stealth hooks by writing back original bytes. */
    HookEntry* entry = g_engine.hooks;
    while (entry) {
        if (!entry->stealth) {
            uintptr_t page_start = (uintptr_t)entry->target & ~0xFFF;
            mprotect((void*)page_start, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC);
            memcpy(entry->target, entry->original_bytes, entry->original_size);
            restore_page_rx(page_start);
            hook_flush_cache(entry->target, entry->original_size);
        }
        entry = entry->next;
    }

    /* HookEntry lifetime note:
     * All HookEntry structs (including trampoline and thunk memory) live inside
     * g_engine.exec_mem (the executable pool). The pool is a single mmap'd region
     * that is released via munmap by the caller after hook_engine_cleanup() returns.
     * Therefore we do NOT iterate the list to free individual entries here — the
     * munmap in the caller frees the entire pool at once.
     *
     * WARNING: Do NOT add malloc()/free() fallback paths for alloc_entry(). If pool
     * allocations ever fall back to malloc, those pointers would be invalid after a
     * munmap and would require explicit free() here. Keep all hook memory in the pool. */

    /* Reset state — the list pointers are now dangling (pool about to be unmapped) */
    g_engine.hooks = NULL;
    g_engine.free_list = NULL;
    g_engine.redirects = NULL;
    g_engine.exec_mem_used = 0;
    g_engine.bulk_cleanup = 0;
    g_engine.batch_mode = 0;
    g_engine.batch_dirty_count = 0;
    g_engine.initialized = 0;

    pthread_mutex_unlock(&g_engine.lock);
    pthread_mutex_destroy(&g_engine.lock);
}
