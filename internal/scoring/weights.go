package scoring

import (
	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/sources"
)

// --- Threat source weights (max achievable: 125) ---
//
// Anchor sources (URLhaus, Feodo): curated data with minimal false
// positives. A fresh anchor (decay > AnchorFreshThreshold) must
// participate for a verdict to reach malicious. No pair of secondary
// sources (ThreatFox + OTX = 50) can reach the threshold (60) alone.
//
// Feodo Tracker: C2 IOC list (abuse.ch) identified by malware config
// analysis. IPv4 only. Weight 40 reflects high signal quality.
const (
	ThreatWeightURLhaus          = 35
	ThreatWeightThreatFox        = 30
	ThreatWeightThreatFoxAnchor  = 40 // when ThreatFox entry is anchor-grade (abuse_ch botnet_cc)
	ThreatWeightOTX              = 20
	ThreatWeightFeodo            = 40 // Anchor source: C2 IOC list (30-day window)

	// ThreatMaxTotal == sum of all base threat weights. The integrity test
	// uses strict equality (sum == ThreatMaxTotal) so that adding a
	// source without updating this constant fails loudly.
	ThreatMaxTotal = 125

	ThreatFoxAnchorReliability = 0.85 // anchor-grade ThreatFox uses Feodo-level reliability
)

// --- False-positive source weights (max achievable: 70) ---
//
// v1 sources: Tranco (30+30). FPWeightTor (10) is reserved for v1.1
// when a Tor exit node source is added — no v1 source produces
// SignalTorExit, so these 10 points are unreachable in v1. FPMaxTotal
// includes them to avoid a weight-sum surprise when the source arrives.
//
// CDN/Cloud hosting is NOT an FP signal. Adversaries routinely rent
// VPS instances in AWS, Azure, and Cloudflare for C2 (see APT10/Cloud
// Hopper). Cloud hosting is enrichment context for the analyst, not
// evidence of benignity.
const (
	FPWeightTrancoTop1M        = 30
	FPWeightTrancoTop100kBonus = 30
	FPWeightTor                = 10 // reserved for v1.1 (no Tor source in v1)

	// FPMaxTotal == sum of all FP weights including reserved (70).
	// Same strict-equality rule as ThreatMaxTotal.
	FPMaxTotal = 70
)

// --- Decision thresholds ---
const (
	ThreatSuspiciousThreshold = 30 // score floor for suspicious; malicious has no score threshold (see Decide)
	FPVetoThreshold           = 60 // only Top 100k can veto malicious (r=0.90); Top 1M alone (r=0.50) cannot
	FPBenignThreshold         = 60

	// AnchorFreshThreshold: minimum decay factor for an anchor to gate
	// malicious. 0.5 means less than one half-life old (30d for IPs,
	// 90d for domains). Below this, the anchor still holds the
	// suspicious floor but cannot enable a malicious verdict.
	AnchorFreshThreshold = 0.5
)

// --- Confidence caps ---
const (
	// One effective voter (one group or one independent source) → max 60.
	// Confidence > 60 needs ≥ 2 independent voters agreeing.
	ConfidenceSingleSourceCap = 60

	// Suspicious uses scaling (noisyOR × 0.5) instead of a hard cap.
	// Max possible: 98 × 0.5 = 49, so suspicious never reaches 50.
	SuspiciousScale = 0.5
)

// --- Anchor sources ---
//
// Anchor sources have curated, confirmed data. The Decide function
// requires at least one anchor vote for a malicious verdict. Without
// an anchor, the maximum verdict is suspicious — no combination of
// secondary sources can override this gate.
var AnchorSources = map[string]bool{
	model.SourceURLhaus: true,
	model.SourceFeodo:   true,
}

// ThreatSourceWeight returns the scoring weight for a threat source.
func ThreatSourceWeight(name string) int {
	switch name {
	case model.SourceURLhaus:
		return ThreatWeightURLhaus
	case model.SourceThreatFox:
		return ThreatWeightThreatFox
	case model.SourceOTX:
		return ThreatWeightOTX
	case model.SourceFeodo:
		return ThreatWeightFeodo
	default:
		return 0
	}
}

// --- Noisy-OR reliability values ---
//
// Each value is the probability that the source is correct when it
// says "yes". Used by the noisy-OR confidence formula:
//   confidence = 1 − Π(1 − r_i)
// Sources that didn't vote (error, not-listed) simply don't
// participate — silence is not evidence against.

var ThreatReliability = map[string]float64{
	model.SourceURLhaus:   0.80,
	model.SourceThreatFox: 0.70,
	model.SourceFeodo:     0.85,
	model.SourceOTX:       0.35,
}

var FPReliability = map[string]float64{
	string(sources.SignalTrancoTop1M):   0.50,
	string(sources.SignalTrancoTop100k): 0.90,
	string(sources.SignalTorExit):       0.30,
}

// Correlated sources share upstream data, so their (1−r) factors
// must not be multiplied independently. For each group, only the
// max reliability among voters is used in the product.
//
// All three abuse.ch sources (URLhaus, ThreatFox, Feodo) share the
// same tracking infrastructure. A ThreatFox entry reported by abuse_ch
// for a botnet_cc is the same observation as the corresponding Feodo
// listing — same team, same C2 analysis, published on two feeds.
var ThreatCorrelationGroups = [][]string{
	{model.SourceURLhaus, model.SourceThreatFox, model.SourceFeodo},
}

// Tranco Top1M and Top100k come from the same ranking list —
// Top100k is strictly stronger evidence than Top1M.
var FPCorrelationGroups = [][]string{
	{string(sources.SignalTrancoTop1M), string(sources.SignalTrancoTop100k)},
}
