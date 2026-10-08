// Test target for coverage instrumentation validation.
// Three-branch control flow per ADR 0017 / ADR 0024.
// Compiled with -fpass-plugin=$<TARGET_FILE:
// EdgeCoveragePass> so the project's own ModulePass
// emits inline AFL-style edge recording against the
// libmlfuzzz3_cov-backed bitmap.

#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        return 1;
    }
    if (argv[1][0] == 'A') {
        printf("path A\n");
        return 0;
    }
    if (argv[1][0] == 'B') {
        printf("path B\n");
        return 0;
    }
    printf("path C\n");
    return 0;
}
