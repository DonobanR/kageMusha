package scoring_test

import (
	"testing"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/scoring"
	"github.com/DonobanR/kagemusha/internal/sources"
)

func TestConfidenceIgnoresFailedSource(t *testing.T) {
	// URLhaus and ThreatFox respond StatusOk, OTX errors out.
	// With noisy-OR, OTX's failure simply means it doesn't vote —
	// it doesn't dilute confidence.
	threat := scoring.ThreatScore([]sources.ThreatEvidence{
		{Source: model.SourceURLhaus, Status: model.StatusOk},
		{Source: model.SourceThreatFox, Status: model.StatusOk},
		{Source: model.SourceOTX, Status: model.StatusError},
	}, nil)

	verdict := scoring.Decide(threat.Score, 0, threat.HasAnchor, threat.HasFreshAnchor)
	if verdict != model.Malicious {
		t.Fatalf("verdict = %v, want malicious (35+30=65, anchor=true)", verdict)
	}

	// Grouped noisy-OR: abuse.ch max(0.80, 0.70)=0.80 → 80%,
	// but effectiveVoters=1 (one group) → single-source cap → 60%.
	// OTX error doesn't participate at all.
	confidence := scoring.Calculate(verdict, threat, scoring.ScoreResult{})
	if confidence != 60 {
		t.Errorf("confidence = %d, want 60 (grouped → single effective voter → cap)", confidence)
	}
}

func TestConfidenceSingleCapableSource(t *testing.T) {
	// Feodo alone: r=0.85 → 85%, single-source cap → 60
	threat := scoring.ScoreResult{
		Voters: []string{model.SourceFeodo}, Yes: 1,
	}
	c := scoring.Calculate(model.Malicious, threat, scoring.ScoreResult{})
	if c != 60 {
		t.Errorf("confidence = %d, want 60 (single-source cap)", c)
	}
}

func TestConfidenceZeroCapable(t *testing.T) {
	c := scoring.Calculate(model.Malicious, scoring.ScoreResult{}, scoring.ScoreResult{})
	if c != 0 {
		t.Errorf("confidence = %d, want 0 (no voters)", c)
	}
}

func TestConfidenceUnknownAlwaysZero(t *testing.T) {
	threat := scoring.ScoreResult{Voters: []string{model.SourceOTX}}
	c := scoring.Calculate(model.Unknown, threat, scoring.ScoreResult{})
	if c != 0 {
		t.Errorf("confidence = %d, want 0 (unknown always returns 0)", c)
	}
}

func TestNoisyORScalesWithReliability(t *testing.T) {
	// Higher reliability source gives higher confidence.
	// Feodo (0.85) + OTX vs URLhaus (0.80) + OTX — both have 2 sources.
	feodoOTX := scoring.ScoreResult{
		Voters: []string{model.SourceFeodo, model.SourceOTX}, Yes: 2,
	}
	urlhausOTX := scoring.ScoreResult{
		Voters: []string{model.SourceURLhaus, model.SourceOTX}, Yes: 2,
	}

	cFeodo := scoring.Calculate(model.Malicious, feodoOTX, scoring.ScoreResult{})
	cURLhaus := scoring.Calculate(model.Malicious, urlhausOTX, scoring.ScoreResult{})

	// Feodo+OTX: 1-(0.15*0.65)=90%, URLhaus+OTX: 1-(0.20*0.65)=87%
	if cFeodo <= cURLhaus {
		t.Errorf("Feodo+OTX confidence (%d) should be > URLhaus+OTX confidence (%d)", cFeodo, cURLhaus)
	}
	if cFeodo != 90 {
		t.Errorf("Feodo+OTX = %d, want 90", cFeodo)
	}
	if cURLhaus != 87 {
		t.Errorf("URLhaus+OTX = %d, want 87", cURLhaus)
	}
}
