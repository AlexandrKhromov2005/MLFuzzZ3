// Test target for exec-server-mediated coverage validation.
// Reads first byte from stdin (where worker.Pool writes
// RunRequest input), branches on value, exits 0. Compiled
// with -fpass-plugin=$<TARGET_FILE:EdgeCoveragePass>
// (ADR 0024) so the project's own ModulePass emits inline
// AFL-style edge recording against the libmlfuzzz3_cov-
// backed bitmap.
//
// Distinct from cov_simple_target (argv-driven) — this one
// matches Pool's runOnce contract (cmd.Stdin = input).

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int c = getchar();
    if (c == EOF) {
        return 1;
    }
    if (c == 'A') {
        printf("path A\n");
        return 0;
    }
    if (c == 'B') {
        printf("path B\n");
        return 0;
    }
    printf("path C\n");
    return 0;
}
