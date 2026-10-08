package main

import (
	"io"
	"os"
	"time"
)

// Reads stdin, sleeps for 10s (longer than any reasonable
// test timeout). Used to verify timeout/cancellation paths.
func main() {
	_, _ = io.Copy(io.Discard, os.Stdin)
	time.Sleep(10 * time.Second)
}
