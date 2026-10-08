/* argv-driven crash fixture for the --target-args end-to-end test
 * (ADR 0040). Behaviour is selected purely by argv, never by stdin:
 *
 *   - with no "crash" argument: drain stdin and exit 0 (never crashes,
 *     for any input);
 *   - given the "crash" argument: dereference a null pointer and die
 *     with SIGSEGV (for any input).
 *
 * A --target-args campaign therefore persists crashes if and only if the
 * argument was delivered through the whole fuzzer CLI -> exec-server CLI
 * -> worker chain, which is exactly what the test asserts.
 *
 * Built with EdgeCoveragePass + libmlfuzzz3_cov, same shape as cov_crash,
 * so it runs under the coverage-enabled exec-server.
 */
#include <string.h>
#include <unistd.h>

int main(int argc, char** argv) {
    /* Drain stdin so the input channel behaves like a real target. */
    char buf[256];
    while (read(0, buf, sizeof(buf)) > 0) {
    }
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "crash") == 0) {
            volatile int* p = 0;
            return *p; /* SIGSEGV */
        }
    }
    return 0;
}
