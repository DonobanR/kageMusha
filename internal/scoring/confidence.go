package scoring

import (
	"math"

	"github.com/DonobanR/kagemusha/internal/model"
)

// Calculate returns a confidence score in [0, 100] for a verdict
// using noisy-OR: confidence = 1 − Π(1 − r_i), where r_i is the
// reliability of each voting source/signal. Correlated sources
// (e.g. URLhaus + ThreatFox) are grouped so their factors don't
// multiply independently.
//
// Sources that errored or didn't vote simply don't participate —
// silence is absence of data, not evidence against.
//
// Caps:
//   - Single effective voter (one group or one independent): max 60%
//   - Suspicious: noisyOR × 0.5 (preserves ordering, max 49%)
//   - Unknown: always 0%
func Calculate(verdict model.Verdict, threat, fp ScoreResult) int {
	switch verdict {
	case model.Malicious:
		raw := noisyOR(threat.Voters, ThreatReliability, ThreatCorrelationGroups, threat.DecayFactors, threat.ReliabilityOverrides)
		c := int(math.Round(raw * 100))
		if effectiveVoters(threat.Voters, ThreatCorrelationGroups) <= 1 && c > ConfidenceSingleSourceCap {
			c = ConfidenceSingleSourceCap
		}
		return c
	case model.Benign:
		raw := noisyOR(fp.Voters, FPReliability, FPCorrelationGroups, nil, nil)
		c := int(math.Round(raw * 100))
		if effectiveVoters(fp.Voters, FPCorrelationGroups) <= 1 && c > ConfidenceSingleSourceCap {
			c = ConfidenceSingleSourceCap
		}
		return c
	case model.Suspicious:
		raw := noisyOR(threat.Voters, ThreatReliability, ThreatCorrelationGroups, threat.DecayFactors, threat.ReliabilityOverrides)
		return int(math.Round(raw * SuspiciousScale * 100))
	case model.Unknown:
		return 0
	default:
		return 0
	}
}

// noisyOR computes 1 − Π(1 − r_i) across the effective voters,
// collapsing correlated groups to their max reliability.
// Returns the raw probability in [0, 1].
func noisyOR(voters []string, reliability map[string]float64, groups [][]string, decay map[string]float64, overrides map[string]float64) float64 {
	if len(voters) == 0 {
		return 0
	}

	memberOf := make(map[string]int)
	for i, g := range groups {
		for _, m := range g {
			memberOf[m] = i
		}
	}

	groupMax := make(map[int]float64)
	var independent []float64

	for _, v := range voters {
		r, ok := reliability[v]
		if !ok {
			continue
		}
		if ovr, has := overrides[v]; has {
			r = ovr
		}
		if f, ok := decay[v]; ok {
			r *= f
		}
		if gIdx, grouped := memberOf[v]; grouped {
			if r > groupMax[gIdx] {
				groupMax[gIdx] = r
			}
		} else {
			independent = append(independent, r)
		}
	}

	product := 1.0
	for _, r := range groupMax {
		product *= (1 - r)
	}
	for _, r := range independent {
		product *= (1 - r)
	}

	return 1 - product
}

// effectiveVoters counts independent voting units: each correlation
// group with at least one voter counts as 1, plus each ungrouped
// voter counts as 1. This prevents correlated sources from bypassing
// the single-source cap.
func effectiveVoters(voters []string, groups [][]string) int {
	memberOf := make(map[string]int)
	for i, g := range groups {
		for _, m := range g {
			memberOf[m] = i
		}
	}

	groupSeen := make(map[int]bool)
	count := 0
	for _, v := range voters {
		if gIdx, grouped := memberOf[v]; grouped {
			if !groupSeen[gIdx] {
				groupSeen[gIdx] = true
				count++
			}
		} else {
			count++
		}
	}
	return count
}
