//go:build linux

package coverage_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"mlfuzzz3/exec-server/internal/coverage"
)

func TestNewChannelSetHappyPath(t *testing.T) {
	libPath := makeFakeLib(t)
	cs, err := coverage.NewChannelSet(libPath, 4)
	if err != nil {
		t.Fatalf("NewChannelSet: %v", err)
	}
	defer func() { _ = cs.Close() }()

	if len(cs.Channels()) != 4 {
		t.Errorf("Channels() len = %d, want 4",
			len(cs.Channels()))
	}
	if len(cs.Announcements()) != 4 {
		t.Errorf("Announcements() len = %d, want 4",
			len(cs.Announcements()))
	}

	// Each channel must carry its set-assigned index.
	for i, ch := range cs.Channels() {
		if ch.Index() != i {
			t.Errorf("Channels()[%d].Index() = %d, want %d",
				i, ch.Index(), i)
		}
	}
}

func TestNewChannelSetRejectsZeroCount(t *testing.T) {
	libPath := makeFakeLib(t)
	_, err := coverage.NewChannelSet(libPath, 0)
	if err == nil {
		t.Fatal("expected error for count=0, got nil")
	}
}

func TestNewChannelSetRejectsNegativeCount(t *testing.T) {
	libPath := makeFakeLib(t)
	_, err := coverage.NewChannelSet(libPath, -1)
	if err == nil {
		t.Fatal("expected error for count=-1, got nil")
	}
}

func TestNewChannelSetRejectsBadLibPath(t *testing.T) {
	_, err := coverage.NewChannelSet("relative/path.so", 4)
	if err == nil {
		t.Fatal("expected error for relative path, got nil")
	}
}

func TestAcquireReleaseHappyPath(t *testing.T) {
	libPath := makeFakeLib(t)
	cs, err := coverage.NewChannelSet(libPath, 2)
	if err != nil {
		t.Fatalf("NewChannelSet: %v", err)
	}
	defer func() { _ = cs.Close() }()

	ctx := context.Background()
	ch1, idx1, err := cs.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire 1: %v", err)
	}
	if idx1 != ch1.Index() {
		t.Errorf("Acquire returned idx=%d, but ch.Index()=%d",
			idx1, ch1.Index())
	}

	ch2, idx2, err := cs.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire 2: %v", err)
	}
	if idx1 == idx2 {
		t.Errorf("Acquire returned same index %d twice", idx1)
	}

	cs.Release(ch1)
	cs.Release(ch2)

	// After release, must be able to acquire again.
	ch3, _, err := cs.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire 3 after release: %v", err)
	}
	cs.Release(ch3)
}

func TestAcquireBlocksWhenExhausted(t *testing.T) {
	libPath := makeFakeLib(t)
	cs, err := coverage.NewChannelSet(libPath, 1)
	if err != nil {
		t.Fatalf("NewChannelSet: %v", err)
	}
	defer func() { _ = cs.Close() }()

	ctx := context.Background()
	ch1, _, err := cs.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire 1: %v", err)
	}

	// Second Acquire should block — verify via timeout ctx.
	ctxTimeout, cancel := context.WithTimeout(
		ctx, 50*time.Millisecond)
	defer cancel()
	_, _, err = cs.Acquire(ctxTimeout)
	if err == nil {
		t.Fatal("Acquire 2 returned nil error while pool exhausted")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded", err)
	}

	// Release ch1; subsequent Acquire must succeed.
	cs.Release(ch1)
	ch2, _, err := cs.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire after release: %v", err)
	}
	cs.Release(ch2)
}

func TestAcquireRespectsCancellation(t *testing.T) {
	libPath := makeFakeLib(t)
	cs, err := coverage.NewChannelSet(libPath, 1)
	if err != nil {
		t.Fatalf("NewChannelSet: %v", err)
	}
	defer func() { _ = cs.Close() }()

	ctx := context.Background()
	ch1, _, err := cs.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire 1: %v", err)
	}
	defer cs.Release(ch1)

	cancelCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	var acqErr error
	go func() {
		defer wg.Done()
		_, _, acqErr = cs.Acquire(cancelCtx)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()
	wg.Wait()

	if !errors.Is(acqErr, context.Canceled) {
		t.Errorf("acqErr = %v, want Canceled", acqErr)
	}
}

func TestIndexOfReturnsCorrectIndex(t *testing.T) {
	libPath := makeFakeLib(t)
	cs, err := coverage.NewChannelSet(libPath, 3)
	if err != nil {
		t.Fatalf("NewChannelSet: %v", err)
	}
	defer func() { _ = cs.Close() }()

	chs := cs.Channels()
	for i, ch := range chs {
		got := cs.IndexOf(ch)
		if got != i {
			t.Errorf("IndexOf(channels[%d]) = %d, want %d",
				i, got, i)
		}
	}

	// Foreign channel → -1.
	otherLib := makeFakeLib(t)
	foreign, err := coverage.NewChannel(otherLib)
	if err != nil {
		t.Fatalf("NewChannel: %v", err)
	}
	defer func() { _ = foreign.Close() }()

	if cs.IndexOf(foreign) != -1 {
		t.Errorf("IndexOf(foreign) = %d, want -1",
			cs.IndexOf(foreign))
	}
}

func TestCloseIdempotentOnSet(t *testing.T) {
	libPath := makeFakeLib(t)
	cs, err := coverage.NewChannelSet(libPath, 2)
	if err != nil {
		t.Fatalf("NewChannelSet: %v", err)
	}

	if err := cs.Close(); err != nil {
		t.Fatalf("Close 1: %v", err)
	}
	// Second Close must not panic.
	_ = cs.Close()
}

func TestConcurrentAcquireRelease(t *testing.T) {
	libPath := makeFakeLib(t)
	cs, err := coverage.NewChannelSet(libPath, 4)
	if err != nil {
		t.Fatalf("NewChannelSet: %v", err)
	}
	defer func() { _ = cs.Close() }()

	ctx := context.Background()
	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			ch, idx, err := cs.Acquire(ctx)
			if err != nil {
				errCh <- err
				return
			}
			if idx < 0 || idx >= 4 {
				errCh <- fmt.Errorf("idx out of range: %d", idx)
				cs.Release(ch)
				return
			}
			// Brief use simulation.
			time.Sleep(time.Millisecond)
			cs.Release(ch)
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent worker error: %v", err)
	}
}
