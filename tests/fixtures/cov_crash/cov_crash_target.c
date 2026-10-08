// Crashing test target for end-to-end crash-path validation
// (ADR 0029). Reads the first byte from stdin (where worker.Pool
// writes RunRequest input) and aborts on any byte with the high
// bit set (~50% of byte values), so a byte-flip mutation campaign
// reaches EXEC_STATUS_CRASH quickly and deterministically for a
// fixed RNG seed. Non-crashing inputs take one of two coverage
// branches so the loop still observes coverage on the way.
//
// Same build shape as cov_stdin: compiled with
// -fpass-plugin=$<TARGET_FILE:EdgeCoveragePass> (ADR 0024) and
// linked against libmlfuzzz3_cov (DT_NEEDED; env activation via
// MLFUZZZ3_COV_FD).

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int c = getchar();
    if (c == EOF) {
        return 1;
    }
    if ((c & 0x80) != 0) {
        abort();
    }
    if (c == 'A') {
        printf("path A\n");
        return 0;
    }
    printf("path other\n");
    return 0;
}
