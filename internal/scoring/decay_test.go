package scoring_test

import (
	"testing"
	"time"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/scoring"
	"github.com/DonobanR/kagemusha/internal/sources"
)

func TestDecayFactorsIPv4(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	evs := []sources.ThreatEvidence{
		{Source: model.SourceURLhaus, Status: model.StatusOk, FirstSeen: "2025-12-31T00:00:00Z"}, // 1 day old
		{Source: model.SourceFeodo, Status: model.StatusOk, FirstSeen: "2025-12-02T00:00:00Z"},   // 30 days (one half-life)
		{Source: model.SourceThreatFox, Status: model.StatusOk, FirstSeen: "2025-11-02T00:00:00Z"}, // 60 days (two half-lives)
	}

	factors := scoring.DecayFactors(model.TypeIPv4, evs, now)
	if factors == nil {
		t.Fatal("expected non-nil factors for IPv4")
	}

	// 1 day: factor ≈ 0.977
	if f := factors[model.SourceURLhaus]; f < 0.97 || f > 0.99 {
		t.Errorf("URLhaus (1 day) factor = %.4f, want ~0.977", f)
	}

	// 30 days (one half-life): factor = 0.5
	if f := factors[model.SourceFeodo]; f < 0.49 || f > 0.51 {
		t.Errorf("Feodo (30 days) factor = %.4f, want ~0.50", f)
	}

	// 60 days (two half-lives): factor = 0.25 (floored)
	if f := factors[model.SourceThreatFox]; f < 0.24 || f > 0.26 {
		t.Errorf("ThreatFox (60 days) factor = %.4f, want ~0.25", f)
	}
}

func TestDecayFactorsDomain(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	evs := []sources.ThreatEvidence{
		{Source: model.SourceURLhaus, Status: model.StatusOk, FirstSeen: "2025-10-03T00:00:00Z"}, // 90 days (one half-life for domain)
	}

	factors := scoring.DecayFactors(model.TypeDomain, evs, now)
	if f := factors[model.SourceURLhaus]; f < 0.49 || f > 0.51 {
		t.Errorf("URLhaus (90 days, domain) factor = %.4f, want ~0.50", f)
	}
}

func TestDecayFactorsHashReturnsNil(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	evs := []sources.ThreatEvidence{
		{Source: model.SourceURLhaus, Status: model.StatusOk, FirstSeen: "2020-01-01T00:00:00Z"},
	}

	factors := scoring.DecayFactors(model.TypeHashSHA256, evs, now)
	if factors != nil {
		t.Errorf("expected nil factors for hash type, got %v", factors)
	}
}

func TestDecayFloor(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	evs := []sources.ThreatEvidence{
		{Source: model.SourceFeodo, Status: model.StatusOk, FirstSeen: "2025-01-01T00:00:00Z"}, // 365 days old
	}

	factors := scoring.DecayFactors(model.TypeIPv4, evs, now)
	if f := factors[model.SourceFeodo]; f != scoring.DecayFloor {
		t.Errorf("ancient IP factor = %.4f, want floor %.2f", f, scoring.DecayFloor)
	}
}

func TestDecaySkipsNonOkAndMissingDate(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	evs := []sources.ThreatEvidence{
		{Source: model.SourceURLhaus, Status: model.StatusError, FirstSeen: "2025-12-01T00:00:00Z"},
		{Source: model.SourceOTX, Status: model.StatusOk, FirstSeen: ""},
	}

	factors := scoring.DecayFactors(model.TypeIPv4, evs, now)
	if _, ok := factors[model.SourceURLhaus]; ok {
		t.Error("errored source should not have a decay factor")
	}
	if _, ok := factors[model.SourceOTX]; ok {
		t.Error("source without FirstSeen should not have a decay factor")
	}
}

func TestDecayFreshEvidenceFactorOne(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	evs := []sources.ThreatEvidence{
		{Source: model.SourceFeodo, Status: model.StatusOk, FirstSeen: "2026-01-01T12:00:00Z"}, // same instant
	}

	factors := scoring.DecayFactors(model.TypeIPv4, evs, now)
	if f := factors[model.SourceFeodo]; f != 1.0 {
		t.Errorf("same-instant factor = %.4f, want 1.0", f)
	}
}

func TestAgeDays(t *testing.T) {
	now := time.Date(2026, 1, 31, 0, 0, 0, 0, time.UTC)

	if d := scoring.AgeDays("2026-01-01T00:00:00Z", now); d != 30 {
		t.Errorf("AgeDays = %d, want 30", d)
	}
	if d := scoring.AgeDays("invalid", now); d != 0 {
		t.Errorf("AgeDays(invalid) = %d, want 0", d)
	}
	if d := scoring.AgeDays("2026-02-15T00:00:00Z", now); d != 0 {
		t.Errorf("AgeDays(future) = %d, want 0", d)
	}
}

func TestDecayDowngradesVerdictOldIP(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	evs := []sources.ThreatEvidence{
		{Source: model.SourceURLhaus, Status: model.StatusOk, FirstSeen: "2025-10-03T00:00:00Z"},   // 90 days → factor floored to 0.25
		{Source: model.SourceThreatFox, Status: model.StatusOk, FirstSeen: "2025-10-03T00:00:00Z"}, // same age
	}

	// Without decay: URLhaus(35) + ThreatFox(30) = 65 ≥ 60 → malicious
	noDecay := scoring.ThreatScore(evs, nil)
	verdictFresh := scoring.Decide(noDecay.Score, 0, noDecay.HasAnchor, noDecay.HasFreshAnchor)
	if verdictFresh != model.Malicious {
		t.Fatalf("fresh verdict = %v, want malicious", verdictFresh)
	}

	// With decay: URLhaus(9) + ThreatFox(8) = 17 < 30, but anchor floor applies
	decay := scoring.DecayFactors(model.TypeIPv4, evs, now)
	withDecay := scoring.ThreatScore(evs, decay)
	verdictOld := scoring.Decide(withDecay.Score, 0, withDecay.HasAnchor, withDecay.HasFreshAnchor)
	if verdictOld != model.Suspicious {
		t.Errorf("old anchor evidence verdict = %v (score=%d), want suspicious (anchor floor)", verdictOld, withDecay.Score)
	}
}

func TestAnchorFloorPreventsUnknown(t *testing.T) {
	// Even with score 0, an anchor vote keeps verdict at suspicious
	verdict := scoring.Decide(5, 0, true, false)
	if verdict != model.Suspicious {
		t.Errorf("anchor with low score verdict = %v, want suspicious", verdict)
	}
}

func TestNoAnchorFloorWithoutAnchor(t *testing.T) {
	// Without anchor, low score stays unknown
	verdict := scoring.Decide(5, 0, false, false)
	if verdict != model.Unknown {
		t.Errorf("no-anchor low score verdict = %v, want unknown", verdict)
	}
}

func TestDecayPrefersLastSeen(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	evs := []sources.ThreatEvidence{
		{
			Source:    model.SourceFeodo,
			Status:    model.StatusOk,
			FirstSeen: "2025-06-01T00:00:00Z", // 214 days old → would floor
			LastSeen:  "2025-12-31T00:00:00Z",  // 1 day old → near 1.0
		},
	}

	factors := scoring.DecayFactors(model.TypeIPv4, evs, now)
	f := factors[model.SourceFeodo]
	if f < 0.97 {
		t.Errorf("Feodo factor = %.4f, want ~0.98 (should use LastSeen, not FirstSeen)", f)
	}
}

func TestDecayFallsBackToFirstSeen(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	evs := []sources.ThreatEvidence{
		{
			Source:    model.SourceURLhaus,
			Status:    model.StatusOk,
			FirstSeen: "2025-12-02T00:00:00Z", // 30 days → 0.5
			LastSeen:  "",                       // no last_seen
		},
	}

	factors := scoring.DecayFactors(model.TypeIPv4, evs, now)
	f := factors[model.SourceURLhaus]
	if f < 0.49 || f > 0.51 {
		t.Errorf("URLhaus factor = %.4f, want ~0.50 (falls back to FirstSeen)", f)
	}
}
