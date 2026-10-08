package main

import (
	"io"
	"os"
	"syscall"
)

// Reads stdin, then replaces self with /bin/sh which
// signals SIGSEGV to itself via `kill -SEGV $$`. We cannot
// produce a signal-terminated Go process directly: Go's
// runtime installs handlers for SIGSEGV/SIGBUS/SIGFPE
// (synchronous signals) that always convert them to
// recoverable panics and a plain os.Exit(2), not signal
// termination. signal.Reset only undoes prior
// signal.Notify calls — it cannot restore OS-default
// action for these signals. The workaround is to hand
// control off to a non-Go process (sh) that dies
// naturally on SIGSEGV.
func main() {
	_, _ = io.Copy(io.Discard, os.Stdin)
	_ = syscall.Exec(
		"/bin/sh",
		[]string{"sh", "-c", "kill -SEGV $$"},
		os.Environ())
}
