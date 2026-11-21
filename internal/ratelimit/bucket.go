package ratelimit

import (
	"context"
	"time"
)

// Bucket is a token-bucket rate limiter. It issues one token per
// interval; multiple goroutines sharing a Bucket are serialized
// at that rate. Zero external dependencies.
type Bucket struct {
	tokens chan struct{}
	done   chan struct{}
}

// New creates a Bucket that issues one token every interval.
// The first token is available immediately so the first caller
// does not wait a full interval.
func New(interval time.Duration) *Bucket {
	b := &Bucket{
		tokens: make(chan struct{}),
		done:   make(chan struct{}),
	}
	go b.fill(interval)
	return b
}

func (b *Bucket) fill(interval time.Duration) {
	// Seed first token immediately.
	select {
	case b.tokens <- struct{}{}:
	case <-b.done:
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-b.done:
			return
		case <-ticker.C:
			select {
			case b.tokens <- struct{}{}:
			case <-b.done:
				return
			}
		}
	}
}

// Wait blocks until a token is available or ctx is cancelled.
func (b *Bucket) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.tokens:
		return nil
	}
}

// Close stops the fill goroutine. Safe to call multiple times
// only if the caller ensures no concurrent Wait calls.
func (b *Bucket) Close() {
	close(b.done)
}
