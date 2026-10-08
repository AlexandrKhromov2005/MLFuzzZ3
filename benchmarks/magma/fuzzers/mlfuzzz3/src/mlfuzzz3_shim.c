/* stdin one-shot driver shim for the Magma comparative benchmark (ADR 0045
 * Step 2).
 *
 * Magma harnesses export the libFuzzer in-process callback
 * LLVMFuzzerTestOneInput (and optionally LLVMFuzzerInitialize) and carry no
 * main(); a fuzzing engine supplies main(). Our exec-server (ADR 0011) drives
 * a target by fork+exec of a standalone binary with the input on stdin, one
 * process per input. This shim is that main(): read ALL of stdin into one
 * buffer, call LLVMFuzzerInitialize once (if present), call
 * LLVMFuzzerTestOneInput exactly once, exit. It is the stdin analogue of LLVM's
 * StandaloneFuzzTargetMain.c (which reads argv files); it matches the
 * fork-exec-per-input model rather than a persistent loop.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

/* Defined by the target harness (extern "C" there → unmangled, matches C).
 * Declared weak, like LLVM's StandaloneFuzzTargetMain.c and Magma's drivers:
 * a target's ./configure honours $LIBS, so this object is pulled into every
 * autoconf conftest link. A weak main lets conftest's own strong main win
 * (no "multiple definition"); a weak callback reference resolves to NULL when
 * absent (no "undefined reference") instead of breaking compiler detection. */
__attribute__((weak)) int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
/* Optional one-time init; weak so absence links cleanly. */
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

__attribute__((weak)) int main(int argc, char **argv) {
    if (LLVMFuzzerInitialize) {
        LLVMFuzzerInitialize(&argc, &argv);
    }

    size_t cap = (size_t)1 << 16;
    size_t len = 0;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (buf == NULL) {
        return 1;
    }
    for (;;) {
        if (len == cap) {
            cap *= 2;
            uint8_t *grown = (uint8_t *)realloc(buf, cap);
            if (grown == NULL) {
                free(buf);
                return 1;
            }
            buf = grown;
        }
        ssize_t n = read(STDIN_FILENO, buf + len, cap - len);
        if (n < 0) {
            free(buf);
            return 1;
        }
        if (n == 0) {
            break;
        }
        len += (size_t)n;
    }

    LLVMFuzzerTestOneInput(buf, len);
    free(buf);
    return 0;
}
