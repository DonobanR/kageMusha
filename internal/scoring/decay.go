package scoring

import (
	"math"
	"time"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/sources"
)

const (
	DecayFloor       = 0.25
	HalfLifeIPDays   = 30
	HalfLifeDomDays  = 90
)

func halfLifeDays(iocType model.IOCType) int {
	switch iocType {
	case model.TypeIPv4, model.TypeIPv6:
		return HalfLifeIPDays
	case model.TypeDomain, model.TypeURL:
		return HalfLifeDomDays
	default:
		return 0
	}
}

// DecayFactors returns a per-source decay multiplier in [DecayFloor, 1.0].
// Hashes never decay (returns nil). IPs decay with a 30-day half-life,
// domains/URLs with 90 days. Prefers LastSeen; falls back to FirstSeen.
// Sources without any date are omitted (no decay entry). Sources with
// an unparseable date get the floor (conservative: assume old).
// The factor floors at 0.25 so old evidence never disappears entirely.
func DecayFactors(iocType model.IOCType, evs []sources.ThreatEvidence, now time.Time) map[string]float64 {
	hl := halfLifeDays(iocType)
	if hl == 0 {
		return nil
	}

	factors := make(map[string]float64, len(evs))
	for _, ev := range evs {
		if ev.Status != model.StatusOk {
			continue
		}
		dateStr := ev.LastSeen
		if dateStr == "" {
			dateStr = ev.FirstSeen
		}
		if dateStr == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, dateStr)
		if err != nil {
			factors[ev.Source] = DecayFloor
			continue
		}
		ageDays := now.Sub(t).Hours() / 24
		if ageDays <= 0 {
			factors[ev.Source] = 1.0
			continue
		}
		factor := math.Pow(2, -ageDays/float64(hl))
		if factor < DecayFloor {
			factor = DecayFloor
		}
		factors[ev.Source] = factor
	}
	return factors
}

// AgeDays returns the age in days for a Reason message, or 0 if
// the date cannot be parsed.
func AgeDays(firstSeen string, now time.Time) int {
	t, err := time.Parse(time.RFC3339, firstSeen)
	if err != nil {
		return 0
	}
	days := int(now.Sub(t).Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}
