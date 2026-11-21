package scoring

import (
	"math"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/sources"
)

// ScoreResult holds a computed score and the data needed by Calculate.
// Returned by ThreatScore and FPScore.
type ScoreResult struct {
	Score                int                // clamped to [0, max], used for decision threshold
	Yes                  int                // sources that voted for the category
	Total                int                // sources that responded with signal (excludes error/timeout)
	HasAnchor            bool               // at least one anchor source voted yes (threat only)
	HasFreshAnchor       bool               // at least one anchor with decay >= AnchorFreshThreshold (or no decay applies)
	Voters               []string           // names of sources/signals that voted yes (for noisy-OR)
	DecayFactors         map[string]float64 // per-source age decay multipliers (nil = no decay)
	ReliabilityOverrides map[string]float64 // per-source reliability overrides (e.g. ThreatFox anchor → 0.85)
}

// ThreatScore aggregates threat evidence into a score and voter list.
// The Score field is clamped to [0, 100]. Weight mapping lives here,
// not in the sources — sources return facts, scoring assigns weights.
// Errored sources do not participate: they don't vote and don't
// penalize confidence (noisy-OR treats silence as absence of data).
//
// When decay is non-nil, each source's weight is multiplied by its
// decay factor so old evidence contributes less to the threshold sum.
func ThreatScore(evs []sources.ThreatEvidence, decay map[string]float64) ScoreResult {
	var r ScoreResult
	r.DecayFactors = decay
	for _, e := range evs {
		switch e.Status {
		case model.StatusError, model.StatusRateLimited, model.StatusTimeout:
			continue
		case model.StatusOk:
			r.Total++
			r.Yes++
			w := ThreatSourceWeight(e.Source)
			if e.Source == model.SourceThreatFox && e.Anchor {
				w = ThreatWeightThreatFoxAnchor
				if r.ReliabilityOverrides == nil {
					r.ReliabilityOverrides = make(map[string]float64)
				}
				r.ReliabilityOverrides[e.Source] = ThreatFoxAnchorReliability
			}
			if f, ok := decay[e.Source]; ok {
				w = int(math.Round(float64(w) * f))
			}
			r.Score += w
			r.Voters = append(r.Voters, e.Source)
			if AnchorSources[e.Source] || e.Anchor {
				r.HasAnchor = true
				if decay == nil {
					r.HasFreshAnchor = true
				} else if f, ok := decay[e.Source]; ok && f >= AnchorFreshThreshold {
					r.HasFreshAnchor = true
				}
			}
		case model.StatusNotListed, model.StatusSuppressed:
			r.Total++
		}
	}
	if r.Score > 100 {
		r.Score = 100
	}
	return r
}

// FPScore aggregates false-positive evidence into a score and voter
// list. The score is clamped to [0, FPMaxTotal]. Yes counts sources
// with at least one signal, not individual signals. Voters tracks
// individual signal names for the noisy-OR calculation.
func FPScore(evs []sources.FPEvidence) ScoreResult {
	var r ScoreResult
	for _, e := range evs {
		if e.Status != model.StatusOk {
			continue
		}
		r.Total++
		for _, s := range e.Signals {
			switch s {
			case sources.SignalTrancoTop1M:
				r.Score += FPWeightTrancoTop1M
			case sources.SignalTrancoTop100k:
				r.Score += FPWeightTrancoTop100kBonus
			case sources.SignalTorExit:
				r.Score += FPWeightTor
			}
			r.Voters = append(r.Voters, string(s))
		}
		if len(e.Signals) > 0 {
			r.Yes++
		}
	}
	if r.Score > FPMaxTotal {
		r.Score = FPMaxTotal
	}
	return r
}
