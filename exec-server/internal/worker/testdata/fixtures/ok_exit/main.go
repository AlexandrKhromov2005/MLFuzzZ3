package main

import (
	"io"
	"os"
)

// Reads stdin to end, exits 0. Baseline "healthy run"
// fixture.
func main() {
	_, _ = io.Copy(io.Discard, os.Stdin)
}
