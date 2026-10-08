// Discriminating parser fixture for the Phase 2 benchmark checkpoint
// (ADR 0032). Same build shape as cov_crash (clang + EdgeCoveragePass +
// libmlfuzzz3_cov via DT_NEEDED), but shaped to separate mutation
// strategies along two independent axes:
//
//   * Positional coverage checkpoints inside the base length L reward
//     systematic positional exploration — the deterministic stage sweeps
//     every offset, havoc hits them stochastically, a single-bit flip is
//     slowest.
//   * Crash A — a single-position condition at depth (the high nibble of
//     buf[k] fully set) — is reachable by a length-preserving walk:
//     byteflip sets the byte directly and the deterministic byte-flip op
//     XORs a small seed byte to 0xFF, but a lone bit flip cannot ratchet
//     there without a coverage gradient at that offset.
//   * Crash B — an input longer than L — is reachable ONLY by a
//     length-growing mutation, isolating havoc.
//
// Either condition aborts. The saved crash input records which one fired:
// a file longer than L is crash B, otherwise crash A.

#include <stdio.h>
#include <stdlib.h>

enum { kBaseLen = 8, kCrashAPos = 5, kHighNibble = 0xF0 };

int main(void) {
    unsigned char buf[256];
    size_t n = fread(buf, 1, sizeof(buf), stdin);

    // Crash B: longer than the base length — only length-growing mutations
    // reach it. Length-preserving strategies can never trigger it.
    if (n > (size_t)kBaseLen) {
        abort();
    }

    // Positional coverage checkpoints within the base length: each matched
    // offset opens a distinct edge.
    int score = 0;
    if (n > 0 && buf[0] == 0x11) {
        score++;
    }
    if (n > 1 && buf[1] == 0x22) {
        score++;
    }
    if (n > 2 && buf[2] == 0x33) {
        score++;
    }
    if (n > 3 && buf[3] == 0x44) {
        score++;
    }
    if (n > 4 && buf[4] == 0x55) {
        score++;
    }
    (void)score;

    // Crash A: a single-position condition at depth, reachable by a
    // length-preserving walk.
    if (n > (size_t)kCrashAPos && (buf[kCrashAPos] & kHighNibble) == kHighNibble) {
        abort();
    }

    return 0;
}
