package ratelimit_test

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/DonobanR/kagemusha/internal/ratelimit"
)

func TestFirstTokenImmediate(t *testing.T) {
	b := ratelimit.New(time.Second)
	defer b.Close()

	start := time.Now()
	if err := b.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("first token took %v, want < 50ms", elapsed)
	}
}

func TestSubsequentTokensThrottled(t *testing.T) {
	interval := 100 * time.Millisecond
	b := ratelimit.New(interval)
	defer b.Close()

	b.Wait(context.Background()) // consume initial token

	start := time.Now()
	b.Wait(context.Background())
	elapsed := time.Since(start)

	if elapsed < 80*time.Millisecond || elapsed > 200*time.Millisecond {
		t.Errorf("second token took %v, want ~%v", elapsed, interval)
	}
}

func TestThreeTokensTiming(t *testing.T) {
	interval := 100 * time.Millisecond
	b := ratelimit.New(interval)
	defer b.Close()

	start := time.Now()
	for i := 0; i < 3; i++ {
		b.Wait(context.Background())
	}
	elapsed := time.Since(start)

	// First immediate, next two at ~100ms each → ~200ms total.
	if elapsed < 150*time.Millisecond || elapsed > 350*time.Millisecond {
		t.Errorf("3 tokens took %v, want ~200ms", elapsed)
	}
}

func TestWaitRespectsContextCancellation(t *testing.T) {
	b := ratelimit.New(time.Hour)
	defer b.Close()

	b.Wait(context.Background()) // consume initial token

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := b.Wait(ctx)
	if err != context.DeadlineExceeded {
		t.Errorf("err = %v, want DeadlineExceeded", err)
	}
}

func TestConcurrentWaitersAreSerialized(t *testing.T) {
	interval := 50 * time.Millisecond
	b := ratelimit.New(interval)
	defer b.Close()

	n := 5
	timestamps := make(chan time.Time, n)

	for i := 0; i < n; i++ {
		go func() {
			b.Wait(context.Background())
			timestamps <- time.Now()
		}()
	}

	var times []time.Time
	for i := 0; i < n; i++ {
		times = append(times, <-timestamps)
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })

	// Consecutive tokens must be spaced by at least ~interval
	// (except first which is immediate). Check last - first >= (n-2)*interval.
	span := times[n-1].Sub(times[0])
	minExpected := time.Duration(n-2) * interval
	if span < minExpected {
		t.Errorf("span = %v, want >= %v", span, minExpected)
	}
}
