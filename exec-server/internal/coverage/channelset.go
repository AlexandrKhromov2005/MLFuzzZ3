package coverage

import (
	"context"
	"fmt"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
)

// ChannelSet manages a fixed-size pool of coverage channels.
// Workers acquire/release channels per Run; each Acquire
// returns the Channel together with its index in the set,
// suitable for the EdgeRunResult.channel_index protocol
// field (ADR 0019 Task 8c).
//
// The buffered availability queue gives natural backpressure:
// Acquire blocks if all N channels currently held. The
// single-worker case (count=1) flows through the same API
// path as multi-worker; no separate code path.
type ChannelSet struct {
	channels  []*Channel
	available chan *Channel
}

// NewChannelSet creates count Channels via NewChannel,
// validating libPath via the first NewChannel call (and
// every subsequent one). Each channel's index field is
// assigned to its position in the slice; subsequent
// Acquire calls then return both pointer and index in O(1).
//
// Returns an error if count <= 0 or any channel creation
// fails. On failure, partially-created channels are closed
// before returning.
func NewChannelSet(libPath string, count int) (*ChannelSet, error) {
	if count <= 0 {
		return nil, fmt.Errorf(
			"channel count must be > 0, got %d", count)
	}

	channels := make([]*Channel, 0, count)
	cleanup := func() {
		for _, ch := range channels {
			_ = ch.Close()
		}
	}

	for i := 0; i < count; i++ {
		ch, err := NewChannel(libPath)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf(
				"create channel %d: %w", i, err)
		}
		ch.index = i
		channels = append(channels, ch)
	}

	available := make(chan *Channel, count)
	for _, ch := range channels {
		available <- ch
	}

	return &ChannelSet{
		channels:  channels,
		available: available,
	}, nil
}

// Channels returns the underlying Channel slice. Caller
// must not modify the slice. Used by main.go to assemble
// ipc.ChannelWithFD entries (Channels()[i].FD() pairs with
// Announcements()[i]).
func (cs *ChannelSet) Channels() []*Channel {
	return cs.channels
}

// Announcements returns ChannelAnnouncement messages for
// all channels, ordered to match Channels(). Index in the
// returned slice corresponds to Channel.Index() (and to
// the channel_index field the peer will see in
// EdgeRunResult).
func (cs *ChannelSet) Announcements() []*ipcv1.ChannelAnnouncement {
	out := make([]*ipcv1.ChannelAnnouncement, len(cs.channels))
	for i, ch := range cs.channels {
		out[i] = ch.Announcement()
	}
	return out
}

// Acquire returns an exclusively-held channel together
// with its index. Blocks if all channels are currently
// held; honours ctx cancellation.
//
// Caller MUST call Release(ch) when done. Reset/Read
// happen between Acquire/Release within the same goroutine
// — concurrent Read on the same channel is not safe.
func (cs *ChannelSet) Acquire(ctx context.Context) (*Channel, int, error) {
	select {
	case ch := <-cs.available:
		return ch, ch.index, nil
	case <-ctx.Done():
		return nil, -1, ctx.Err()
	}
}

// Release returns the channel to the available pool. Must
// match exactly one prior Acquire (no double-release; the
// pool size is enforced via the buffered chan capacity =
// count, so a stray double-release would panic on send to
// a full chan).
func (cs *ChannelSet) Release(ch *Channel) {
	cs.available <- ch
}

// IndexOf returns ch's position in the set, or -1 if ch
// is not part of this set. O(N) scan; prefer the index
// returned by Acquire when available. Provided as fallback
// for callers holding a Channel pointer not obtained via
// Acquire.
func (cs *ChannelSet) IndexOf(ch *Channel) int {
	for i, c := range cs.channels {
		if c == ch {
			return i
		}
	}
	return -1
}

// Close closes all channels. Idempotent; safe to call
// after Channel.Close on individual channels. Returns the
// first close error encountered.
func (cs *ChannelSet) Close() error {
	var firstErr error
	for _, ch := range cs.channels {
		if err := ch.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
