// mlfuzzz3 coverage instrumentation library (Stage 1+2
// per ADR 0017, ADR 0024).
//
// Stage 1 path: target binary compiled с
// -fsanitize-coverage=trace-pc-guard emits callbacks
// (__sanitizer_cov_trace_pc_guard*) on every basic block
// transition; this library logs them as edge transitions
// in a 64 KiB shared bitmap.
//
// Stage 2 path (ADR 0024 §Runtime): target binary
// instrumented by the project's own EdgeCoveragePass
// inlines the same AFL-style XOR + saturating-8-bit
// increment directly. The inline IR loads the bitmap
// base from the exported pointer __mlfuzzz3_cov_map
// rather than going through a callback.
//
// Both paths write the same 64 KiB region (one runtime,
// one mmap, one bitmap; different ABIs). Symbols don't
// conflict: __sanitizer_cov_trace_pc_guard* is the
// vendor sanitizer ABI; __mlfuzzz3_cov_map is the
// project's own namespace.
//
// Activation: env var MLFUZZZ3_COV_FD must contain a
// valid fd to a 64 KiB writable shared region (typically
// memfd_create'd by the orchestrator and inherited via
// ExtraFiles).

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mlfuzzz3_branch.h"

// Coverage map size: 64 KiB. Per ADR 0017, AFL-standard
// value. Hardcoded; configurability deferred to Phase 2.
#define COV_MAP_SIZE (1u << 16)

// Shared coverage bitmap pointer. Exported per ADR 0024
// §Runtime: the Stage 2 EdgeCoveragePass emits an
// external `ptr @__mlfuzzz3_cov_map` reference and loads
// the value at each instrumented block. The constructor
// always backs this with a writable region of COV_MAP_SIZE
// (ADR 0042 A2): the real shared bitmap when MLFUZZZ3_COV_FD
// is set, else a private throwaway fallback, so the Stage 2
// inline IR (which does not NULL-check) is safe even when an
// instrumented binary runs outside the harness. It stays
// NULL only in the degenerate case where even the anonymous
// fallback mmap fails; the Stage 1 callbacks still NULL-check
// to cover that.
uint8_t *__mlfuzzz3_cov_map = NULL;

// Thread-local previous edge ID for AFL XOR hashing:
// edge_id = (prev_loc >> 1) ^ cur_loc.
// Initial 0 = "no previous edge"; first callback xors
// against 0 (>> 1 = 0), so initial edge index = cur_loc.
static __thread uint32_t g_prev_loc = 0;

// Sanitizer-coverage interface: invoked once at startup
// by the runtime, given the bounds of the guard array.
// We assign sequential edge IDs starting from 1 (0 is
// reserved for "uninitialized guard"), so each guard
// becomes a unique non-zero id within COV_MAP_SIZE.
void __sanitizer_cov_trace_pc_guard_init(
    uint32_t *start, uint32_t *stop) {
    static uint32_t next_id = 1;
    for (uint32_t *p = start; p < stop; ++p) {
        if (*p != 0) {
            continue;  // already initialized
        }
        *p = next_id++;
    }
}

// Sanitizer-coverage interface: fires on every basic
// block transition. Saturating 8-bit increment of the
// bitmap byte at the XOR-hashed index. Non-atomic per
// AFL precedent (single-byte race rarely catastrophic;
// accept it for simplicity).
void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    if (__mlfuzzz3_cov_map == NULL) {
        return;
    }
    const uint32_t cur_loc = *guard;
    const uint32_t idx = (g_prev_loc >> 1) ^ cur_loc;
    const uint32_t bitmap_idx = idx & (COV_MAP_SIZE - 1);
    if (__mlfuzzz3_cov_map[bitmap_idx] < 255) {
        __mlfuzzz3_cov_map[bitmap_idx]++;
    }
    g_prev_loc = cur_loc;
}

// Anonymous fallback map for unharnessed runs (ADR 0042 A2+B1).
// When no valid coverage fd is available, back __mlfuzzz3_cov_map
// with a private throwaway region of the same COV_MAP_SIZE so the
// Stage 2 inline IR's writes land in-bounds instead of
// dereferencing NULL. The region is never read back — it only
// keeps an instrumented binary runnable without the harness
// (build-time helpers, standalone debugging). Its bytes never
// reach the edge frontier or metrics: those come from the real
// shared bitmap via the fd, and a process without the fd is not
// connected to the server. Cold path only (once per process at
// startup); the fd path below is untouched, so the hot path under
// the harness is identical to pre-0042.
static void map_fallback(void) {
    void *map = mmap(NULL, COV_MAP_SIZE,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map != MAP_FAILED) {
        __mlfuzzz3_cov_map = (uint8_t *)map;
    }
}

// Constructor: runs once before main(). With MLFUZZZ3_COV_FD set
// it mmaps the real shared bitmap; otherwise (unset, malformed, or
// mmap failure) it falls back to a private throwaway map (ADR 0042
// A2) so an instrumented binary never SIGSEGVs on its first edge
// outside the harness. Priority 101 = slightly after stdlib init
// (priority 100), before user code.
__attribute__((constructor(101)))
static void mlfuzzz3_cov_init(void) {
    const char *fd_str = getenv("MLFUZZZ3_COV_FD");
    if (fd_str == NULL) {
        // No harness fd: silent per ADR 0017 success metric #6,
        // but still back the map with a fallback (ADR 0042 A2).
        map_fallback();
        return;
    }
    char *endp = NULL;
    const long fd_long = strtol(fd_str, &endp, 10);
    if (endp == fd_str || *endp != '\0' || fd_long < 0) {
        fprintf(stderr,
            "mlfuzzz3_cov: MLFUZZZ3_COV_FD malformed: %s\n",
            fd_str);
        map_fallback();
        return;
    }
    const int fd = (int)fd_long;
    void *map = mmap(NULL, COV_MAP_SIZE,
                     PROT_READ | PROT_WRITE,
                     MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        fprintf(stderr,
            "mlfuzzz3_cov: mmap fd %d failed: %s\n",
            fd, strerror(errno));
        map_fallback();
        return;
    }
    __mlfuzzz3_cov_map = (uint8_t *)map;
}

// ============================================================
// Branch-value channel (ADR 0033). Fully independent of the
// edge path above: separate env var, separate SHM segment,
// separate globals. The edge bitmap remains the single source
// of truth for coverage; this channel only logs comparison
// operands for the later concolic stage (0034+).
// ============================================================

// Branch segment base + record array. NULL/NULL when the
// channel is inert (MLFUZZZ3_BRANCH_FD unset, or mmap/fstat
// failed). g_branch_hdr is published last in the constructor,
// so a non-NULL value implies g_branch_records is valid too.
static struct fuzzer_rt_branch_header *g_branch_hdr = NULL;
static struct fuzzer_rt_branch_record *g_branch_records = NULL;

// Branch-tracing hook. Called by pass-instrumented targets on
// every user-level icmp (the LLVM pass emits an external
// reference to this symbol — exported, default visibility).
// Append-only: writes one record while count < capacity,
// otherwise sets overflow_flag and drops (segment is never
// grown, ADR 0033 overflow contract). Non-atomic, matching
// the edge path's single-byte-race precedent — the branch
// channel assumes a single-threaded target ordering for
// deterministic replay; multi-thread support is deferred.
void fuzzer_rt_log_branch_cmp(uint32_t site_id, uint64_t lhs,
                              uint64_t rhs, uint8_t predicate,
                              uint8_t bit_width) {
    if (g_branch_hdr == NULL) {
        return;  // inert
    }
    const uint32_t idx = g_branch_hdr->count;
    if (idx >= g_branch_hdr->capacity) {
        g_branch_hdr->overflow_flag = 1;
        return;  // drop; do not grow the segment
    }
    struct fuzzer_rt_branch_record *rec = &g_branch_records[idx];
    rec->site_id = site_id;
    rec->predicate = predicate;
    rec->bit_width = bit_width;
    rec->reserved = 0;
    rec->lhs = lhs;
    rec->rhs = rhs;
    g_branch_hdr->count = idx + 1;
}

// Constructor: mirror of mlfuzzz3_cov_init for the branch
// segment. mmaps the fd from MLFUZZZ3_BRANCH_FD and derives
// capacity from the physical segment size (orchestrator owns
// sizing); leaves the channel inert if the var is unset or
// the fd cannot be mapped.
__attribute__((constructor(101)))
static void mlfuzzz3_branch_init(void) {
    const char *fd_str = getenv("MLFUZZZ3_BRANCH_FD");
    if (fd_str == NULL) {
        return;  // inert
    }
    char *endp = NULL;
    const long fd_long = strtol(fd_str, &endp, 10);
    if (endp == fd_str || *endp != '\0' || fd_long < 0) {
        fprintf(stderr,
            "mlfuzzz3_cov: MLFUZZZ3_BRANCH_FD malformed: %s\n",
            fd_str);
        return;
    }
    const int fd = (int)fd_long;
    struct stat st;
    if (fstat(fd, &st) != 0) {
        fprintf(stderr,
            "mlfuzzz3_cov: fstat branch fd %d failed: %s\n",
            fd, strerror(errno));
        return;
    }
    const size_t seg_size = (size_t)st.st_size;
    if (seg_size < sizeof(struct fuzzer_rt_branch_header)) {
        fprintf(stderr,
            "mlfuzzz3_cov: branch segment too small: %zu\n",
            seg_size);
        return;
    }
    void *map = mmap(NULL, seg_size,
                     PROT_READ | PROT_WRITE,
                     MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        fprintf(stderr,
            "mlfuzzz3_cov: mmap branch fd %d failed: %s\n",
            fd, strerror(errno));
        return;
    }
    struct fuzzer_rt_branch_header *hdr = map;
    size_t cap =
        (seg_size - sizeof(struct fuzzer_rt_branch_header)) /
        sizeof(struct fuzzer_rt_branch_record);
    if (cap > UINT32_MAX) {
        cap = UINT32_MAX;
    }
    hdr->count = 0;
    hdr->overflow_flag = 0;
    hdr->reserved = 0;
    hdr->capacity = (uint32_t)cap;
    g_branch_records = (struct fuzzer_rt_branch_record *)
        ((uint8_t *)map +
         sizeof(struct fuzzer_rt_branch_header));
    g_branch_hdr = hdr;  // publish last
}
