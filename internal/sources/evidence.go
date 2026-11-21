package sources

import (
	"context"

	"github.com/DonobanR/kagemusha/internal/model"
)

// ThreatEvidence is what a threat source found about an IOC.
// The source returns facts; scoring assigns weights.
type ThreatEvidence struct {
	Source        string
	Status        model.SourceStatus
	MalwareFamily string
	Reference     string // link to the original report
	FirstSeen     string // ISO 8601 timestamp from the source
	LastSeen      string // most recent activity; decay prefers this over FirstSeen
	Extra         string // operational context (port, status) for the analyst
	Anchor        bool   // entry-level anchor: client certifies this entry is curated/confirmed
}

// FPEvidence is what a false-positive source found about an IOC.
type FPEvidence struct {
	Source  string
	Status  model.SourceStatus
	Signals []FPSignal // only meaningful when Status == StatusOk
}

// FPSignal identifies a specific benign signal. Scoring maps each
// signal to its weight via scoring/weights.go constants.
type FPSignal string

const (
	SignalTrancoTop1M   FPSignal = "tranco_top_1m"
	SignalTrancoTop100k FPSignal = "tranco_top_100k"
	SignalTorExit       FPSignal = "tor_exit"
)

// ThreatSource queries a threat intelligence feed.
//
// Error contract: operational failures (HTTP errors, timeouts, rate
// limits, malformed responses) are encoded in ThreatEvidence.Status
// with a nil error. A non-nil error means a programmer bug in the
// caller (nil ctx, IOC type not in AppliesTo). The CLI treats non-nil
// errors as fatal.
type ThreatSource interface {
	Name() string
	AppliesTo(model.IOCType) bool
	Lookup(ctx context.Context, ioc model.IOC) (ThreatEvidence, error)
}

// FPSource checks for benign infrastructure signals.
//
// Same error contract as ThreatSource.
type FPSource interface {
	Name() string
	AppliesTo(model.IOCType) bool
	Check(ctx context.Context, ioc model.IOC) (FPEvidence, error)
}

// EnrichmentSource adds context that does NOT affect the score.
// Cloud hosting, ASN, geolocation — data for the analyst, not
// evidence for the verdict.
type EnrichmentSource interface {
	Name() string
	AppliesTo(model.IOCType) bool
	Enrich(ctx context.Context, ioc model.IOC) ([]string, error)
}
