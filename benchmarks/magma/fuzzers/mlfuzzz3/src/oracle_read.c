/* Dump producer_buffer reach/trigger counters from a Magma canaries.raw file
 * (ADR 0045 Step 4 oracle-axis gate).
 *
 * The Magma monitor reads the consumer_buffer through the live producer/
 * consumer handshake (monitor.c fetch_file), which is built for polling a
 * running fuzzer. For an offline corpus replay — where many short-lived
 * fork-exec producers accumulate into one shared file and we want the final
 * ground truth — we read the producer_buffer directly, bypassing the handshake.
 * Using the vendored storage.h layout avoids any offset guessing.
 *
 * Output: one "NAME REACHED TRIGGERED" line per non-empty canary slot.
 * Build:  clang-20 -I <magma>/src oracle_read.c -o oracle_read
 */
#include "storage.h"
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s CANARIES_FILE\n", argv[0]);
        return 2;
    }
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 2;
    }
    pstored_data_t d = mmap(0, FILESIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (d == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    for (size_t i = 0; i < BUFFERLEN; ++i) {
        canary_t *c = &d->producer_buffer[i];
        if (c->name[0] == '\0') {
            continue;
        }
        printf("%s %llu %llu\n", c->name, c->reached, c->triggered);
    }
    return 0;
}
