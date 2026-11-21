package scoring

import "github.com/DonobanR/kagemusha/internal/model"

// Decide applies the verdict decision table. Pure and total: every
// input tuple maps to exactly one Verdict.
//
// Malicious = a fresh anchor (decay factor >= AnchorFreshThreshold) and no
// FP veto (fpScore < FPVetoThreshold). There is no score threshold: the
// verdict states what a curated source asserts; how much that is
// corroborated is the job of the confidence value (single correlation
// group caps at 60). Non-anchor sources alone can never yield malicious,
// and a stale anchor downgrades to suspicious.
//
// Anchor floor: if any anchor listed the IOC (fresh or stale), the
// verdict never drops below suspicious — unless strong FP evidence
// (Tranco top 100k, FP >= 60) overrides it to benign.
//
// Suspicious floor at 30: any source with real evidence pushes to
// suspicious. Only OTX alone (20) stays in unknown.
func Decide(threatScore, fpScore int, hasAnchor, hasFreshAnchor bool) model.Verdict {
	switch {
	case hasFreshAnchor && fpScore < FPVetoThreshold:
		return model.Malicious
	case threatScore >= ThreatSuspiciousThreshold:
		return model.Suspicious
	case hasAnchor && fpScore < FPBenignThreshold:
		return model.Suspicious
	case fpScore >= FPBenignThreshold:
		return model.Benign
	default:
		return model.Unknown
	}
}
