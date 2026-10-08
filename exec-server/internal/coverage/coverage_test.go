//go:build linux

package coverage_test

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"mlfuzzz3/exec-server/internal/coverage"
)

// makeFakeLib creates a temp file that NewChannel will accept
// as a regular-file LD_PRELOAD path. Content irrelevant —
// NewChannel does not dlopen it.
func makeFakeLib(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "fake-cov-*.so")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	path := f.Name()
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return path
}

func TestNewChannelHappyPath(t *testing.T) {
	libPath := makeFakeLib(t)
	ch, err := coverage.NewChannel(libPath)
	if err != nil {
		t.Fatalf("NewChannel: %v", err)
	}
	defer func() { _ = ch.Close() }()

	if ch.FD() < 0 {
		t.Errorf("FD = %d, want >= 0", ch.FD())
	}
	if ch.LibPath() != libPath {
		t.Errorf("LibPath = %q, want %q",
			ch.LibPath(), libPath)
	}
	if ch.MemfdFile() == nil {
		t.Error("MemfdFile returned nil")
	}
	if ch.Index() != -1 {
		t.Errorf("standalone Channel Index() = %d, "+
			"want -1", ch.Index())
	}

	ann := ch.Announcement()
	if ann == nil {
		t.Fatal("Announcement returned nil")
	}
	edge := ann.GetEdge()
	if edge == nil {
		t.Fatal("Announcement.GetEdge() = nil")
	}
	if edge.Length != coverage.MapSize {
		t.Errorf("descriptor length = %d, want %d",
			edge.Length, coverage.MapSize)
	}
}

func TestNewChannelRejectsRelativePath(t *testing.T) {
	_, err := coverage.NewChannel("relative/path.so")
	if err == nil {
		t.Fatal("expected error for relative path, got nil")
	}
}

func TestNewChannelRejectsMissingFile(t *testing.T) {
	_, err := coverage.NewChannel("/nonexistent/path.so")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestNewChannelRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := coverage.NewChannel(dir)
	if err == nil {
		t.Fatal("expected error for directory, got nil")
	}
}

func TestResetZeroesBitmap(t *testing.T) {
	libPath := makeFakeLib(t)
	ch, err := coverage.NewChannel(libPath)
	if err != nil {
		t.Fatalf("NewChannel: %v", err)
	}
	defer func() { _ = ch.Close() }()

	scratch := make([]byte, 32)
	for i := range scratch {
		scratch[i] = 0xAB
	}
	if _, err := syscall.Pwrite(ch.FD(), scratch, 0); err != nil {
		t.Fatalf("pwrite: %v", err)
	}

	bm, err := ch.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(bm[:32], scratch) {
		t.Fatalf(
			"Read before Reset did not reflect direct write")
	}

	if err := ch.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	bm, err = ch.Read()
	if err != nil {
		t.Fatalf("Read after Reset: %v", err)
	}
	for i, b := range bm {
		if b != 0 {
			t.Fatalf("byte %d = %d after Reset, want 0",
				i, b)
		}
	}
}

func TestReadReturnsCopy(t *testing.T) {
	libPath := makeFakeLib(t)
	ch, err := coverage.NewChannel(libPath)
	if err != nil {
		t.Fatalf("NewChannel: %v", err)
	}
	defer func() { _ = ch.Close() }()

	bm1, err := ch.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	bm1[0] = 0xFF

	bm2, err := ch.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if bm2[0] != 0 {
		t.Errorf(
			"Read() returned shared buffer; bm2[0] = %d, "+
				"want 0", bm2[0])
	}
}

func TestCloseIdempotent(t *testing.T) {
	libPath := makeFakeLib(t)
	ch, err := coverage.NewChannel(libPath)
	if err != nil {
		t.Fatalf("NewChannel: %v", err)
	}

	if err := ch.Close(); err != nil {
		t.Fatalf("Close 1: %v", err)
	}
	_ = ch.Close()

	if err := ch.Reset(); err == nil {
		t.Error("Reset on closed channel returned nil error")
	}
}

func TestMapSizeIs64KiB(t *testing.T) {
	if coverage.MapSize != 65536 {
		t.Errorf("MapSize = %d, want 65536",
			coverage.MapSize)
	}
}

func TestLibPathStability(t *testing.T) {
	libPath := makeFakeLib(t)
	abs, err := filepath.Abs(libPath)
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	ch, err := coverage.NewChannel(abs)
	if err != nil {
		t.Fatalf("NewChannel: %v", err)
	}
	defer func() { _ = ch.Close() }()
	if ch.LibPath() != abs {
		t.Errorf("LibPath = %q, want %q",
			ch.LibPath(), abs)
	}
}
