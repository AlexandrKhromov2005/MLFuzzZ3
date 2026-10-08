package main

import (
	"io"
	"os"
	"syscall"
)

// argv-driven crash fixture for TargetArgs delivery (ADR 0040). Reads
// stdin to end, then crashes with SIGSEGV if and only if it was invoked
// with the literal "crash" argument; otherwise it exits 0. The SIGSEGV is
// produced by handing off to /bin/sh, because Go's runtime converts
// synchronous signals to recoverable panics (see crash_segv for the full
// rationale).
func main() {
	_, _ = io.Copy(io.Discard, os.Stdin)
	for _, arg := range os.Args[1:] {
		if arg == "crash" {
			_ = syscall.Exec(
				"/bin/sh",
				[]string{"sh", "-c", "kill -SEGV $$"},
				os.Environ())
		}
	}
}
