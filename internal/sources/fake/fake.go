package fake

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/sources"
)

// BlockingThreatSource is a test double that blocks until ctx is cancelled
// or BlockFor elapses. It implements sources.ThreatSource.
type BlockingThreatSource struct {
	SourceName string
	BlockFor   time.Duration
}

func (b *BlockingThreatSource) Name() string                    { return b.SourceName }
func (b *BlockingThreatSource) AppliesTo(_ model.IOCType) bool  { return true }

func (b *BlockingThreatSource) Lookup(ctx context.Context, _ model.IOC) (sources.ThreatEvidence, error) {
	select {
	case <-time.After(b.BlockFor):
		return sources.ThreatEvidence{Source: b.SourceName, Status: model.StatusOk}, nil
	case <-ctx.Done():
		return sources.ThreatEvidence{Source: b.SourceName, Status: model.StatusTimeout}, nil
	}
}

// FailingThreatSource always returns StatusError. For exit code 3 tests.
type FailingThreatSource struct {
	SourceName string
}

func (f *FailingThreatSource) Name() string                    { return f.SourceName }
func (f *FailingThreatSource) AppliesTo(_ model.IOCType) bool  { return true }

func (f *FailingThreatSource) Lookup(_ context.Context, _ model.IOC) (sources.ThreatEvidence, error) {
	return sources.ThreatEvidence{Source: f.SourceName, Status: model.StatusError}, nil
}

// CancelOnNthThreatSource cancels the given context on the Nth call to Lookup.
// Deterministic alternative to time-based cancellation for tests.
// Thread-safe: uses atomic counter for concurrent callers.
type CancelOnNthThreatSource struct {
	SourceName string
	Limit      int
	Cancel     context.CancelFunc
	calls      atomic.Int32
}

func (c *CancelOnNthThreatSource) Name() string                    { return c.SourceName }
func (c *CancelOnNthThreatSource) AppliesTo(_ model.IOCType) bool  { return true }

func (c *CancelOnNthThreatSource) Lookup(_ context.Context, _ model.IOC) (sources.ThreatEvidence, error) {
	n := c.calls.Add(1)
	if int(n) == c.Limit {
		c.Cancel()
	}
	return sources.ThreatEvidence{Source: c.SourceName, Status: model.StatusOk}, nil
}

// BuggyThreatSource returns a non-nil error, violating the error contract.
// Used to test that RunScan propagates the error instead of calling os.Exit.
type BuggyThreatSource struct {
	SourceName string
}

func (b *BuggyThreatSource) Name() string                   { return b.SourceName }
func (b *BuggyThreatSource) AppliesTo(_ model.IOCType) bool { return true }

func (b *BuggyThreatSource) Lookup(_ context.Context, _ model.IOC) (sources.ThreatEvidence, error) {
	return sources.ThreatEvidence{}, fmt.Errorf("unexpected nil pointer")
}

// BuggyFPSource is the FP equivalent of BuggyThreatSource.
type BuggyFPSource struct {
	SourceName string
}

func (b *BuggyFPSource) Name() string                   { return b.SourceName }
func (b *BuggyFPSource) AppliesTo(_ model.IOCType) bool { return true }

func (b *BuggyFPSource) Check(_ context.Context, _ model.IOC) (sources.FPEvidence, error) {
	return sources.FPEvidence{}, fmt.Errorf("unexpected nil pointer")
}

// TimestampThreatSource records the wall-clock time of each Lookup
// call. Thread-safe for concurrent callers. Used to verify that
// rate-limited sources are actually throttled.
type TimestampThreatSource struct {
	SourceName string
	mu         sync.Mutex
	Calls      []time.Time
}

func (t *TimestampThreatSource) Name() string                   { return t.SourceName }
func (t *TimestampThreatSource) AppliesTo(_ model.IOCType) bool { return true }

func (t *TimestampThreatSource) Lookup(_ context.Context, _ model.IOC) (sources.ThreatEvidence, error) {
	t.mu.Lock()
	t.Calls = append(t.Calls, time.Now())
	t.mu.Unlock()
	return sources.ThreatEvidence{Source: t.SourceName, Status: model.StatusNotListed}, nil
}

// StubThreatSource returns a fixed evidence on every Lookup.
type StubThreatSource struct {
	SourceName string
	Evidence   sources.ThreatEvidence
}

func (s *StubThreatSource) Name() string                   { return s.SourceName }
func (s *StubThreatSource) AppliesTo(_ model.IOCType) bool { return true }

func (s *StubThreatSource) Lookup(_ context.Context, _ model.IOC) (sources.ThreatEvidence, error) {
	return s.Evidence, nil
}

// Compile-time interface checks.
var (
	_ sources.ThreatSource = (*BlockingThreatSource)(nil)
	_ sources.ThreatSource = (*FailingThreatSource)(nil)
	_ sources.ThreatSource = (*CancelOnNthThreatSource)(nil)
	_ sources.ThreatSource = (*BuggyThreatSource)(nil)
	_ sources.ThreatSource = (*TimestampThreatSource)(nil)
	_ sources.ThreatSource = (*StubThreatSource)(nil)
	_ sources.FPSource     = (*BuggyFPSource)(nil)
)
