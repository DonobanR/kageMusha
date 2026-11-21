package scoring_test

import (
	"testing"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/scoring"
	"github.com/DonobanR/kagemusha/internal/sources"
)

// --- Decide ---

func TestDecide(t *testing.T) {
	tests := []struct {
		name       string
		threat, fp int
		anchor     bool
		fresh      bool // HasFreshAnchor
		want       model.Verdict
	}{
		// Core table (with fresh anchor)
		{"high threat low fp with fresh anchor", 65, 10, true, true, model.Malicious},
		{"high threat high fp (fp veto)", 65, 70, true, true, model.Suspicious},
		{"low threat high fp no anchor", 20, 70, false, false, model.Benign},
		{"low threat low fp", 20, 10, false, false, model.Unknown},

		// Anchor gate: high threat without anchor → suspicious
		{"high threat low fp NO anchor", 65, 10, false, false, model.Suspicious},
		{"max score NO anchor → suspicious, never malicious", 100, 0, false, false, model.Suspicious},
		{"threat=60 fp=0 no anchor → suspicious", 60, 0, false, false, model.Suspicious},

		// Fresh anchor gate
		{"threat=60 fp=0 fresh anchor → malicious", 60, 0, true, true, model.Malicious},
		{"threat=60 fp=59 fresh anchor → malicious", 60, 59, true, true, model.Malicious},
		{"threat=60 fp=60 fresh anchor → suspicious (Top100k veto)", 60, 60, true, true, model.Suspicious},

		// Stale anchor: cannot gate malicious even at high threat
		{"threat=65 fp=0 stale anchor → suspicious", 65, 0, true, false, model.Suspicious},

		// FP veto: only Top 100k (FP=60) can veto, not Top 1M alone (FP=30)
		{"threat=60 fp=30 fresh anchor → malicious (Top1M no veto)", 60, 30, true, true, model.Malicious},

		// Suspicious threshold at 30: threat evidence blocks benign
		{"threat=59 fp=60 → suspicious (threat blocks benign)", 59, 60, false, false, model.Suspicious},
		{"threat=30 fp=60 → suspicious (floor)", 30, 60, false, false, model.Suspicious},
		{"threat=29 fp=60 → benign (below floor)", 29, 60, false, false, model.Benign},
		{"threat=59 fp=59 → suspicious", 59, 59, false, false, model.Suspicious},

		// Real weight combinations (fresh anchor where applicable)
		{"urlhaus+threatfox (65) fresh anchor → malicious", 65, 0, true, true, model.Malicious},
		{"urlhaus+otx (55) fresh anchor → malicious", 55, 0, true, true, model.Malicious},
		{"threatfox+otx (50) suspicious", 50, 0, false, false, model.Suspicious},
		{"all three (85) fresh anchor → malicious", 85, 0, true, true, model.Malicious},
		{"urlhaus alone (35) fresh anchor → malicious (no score threshold)", 35, 0, true, true, model.Malicious},
		{"feodo alone (40) fresh anchor → malicious (no score threshold)", 40, 0, true, true, model.Malicious},
		{"otx alone (20) unknown", 20, 0, false, false, model.Unknown},

		// Extremes
		{"zero/zero → unknown", 0, 0, false, false, model.Unknown},
		{"100/0 fresh anchor → malicious", 100, 0, true, true, model.Malicious},
		{"100/0 no anchor → suspicious", 100, 0, false, false, model.Suspicious},
		{"0/100 → benign", 0, 100, false, false, model.Benign},
		{"100/100 → suspicious", 100, 100, true, true, model.Suspicious},

		// Middle zones
		{"threat=40 fp=45 → suspicious", 40, 45, false, false, model.Suspicious},
		{"threat=10 fp=45 → unknown", 10, 45, false, false, model.Unknown},

		// Anchor floor vs benign: strong FP overrides anchor floor
		{"stale anchor floor holds without FP", 15, 0, true, false, model.Suspicious},
		{"stale anchor floor yields to strong FP → benign", 15, 60, true, false, model.Benign},
		{"fresh anchor, any score, no FP → malicious", 15, 0, true, true, model.Malicious},
		{"anchor floor yields to strong FP even when fresh", 15, 60, true, true, model.Benign},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := scoring.Decide(tc.threat, tc.fp, tc.anchor, tc.fresh); got != tc.want {
				t.Errorf("Decide(%d, %d, anchor=%v, fresh=%v) = %v, want %v",
					tc.threat, tc.fp, tc.anchor, tc.fresh, got, tc.want)
			}
		})
	}
}

// --- Confidence: malicious (noisy-OR) ---

func TestCalculateMalicious(t *testing.T) {
	tests := []struct {
		name   string
		voters []string
		yes    int
		want   int
	}{
		{"no sources", nil, 0, 0},
		// Feodo alone: r=0.85 → 85%, single effective voter cap → 60
		{"feodo alone", []string{model.SourceFeodo}, 1, 60},
		// URLhaus alone: r=0.80 → 80%, single effective voter cap → 60
		{"urlhaus alone", []string{model.SourceURLhaus}, 1, 60},
		// OTX alone: r=0.35 → 35%, below cap
		{"otx alone (low reliability)", []string{model.SourceOTX}, 1, 35},
		// URLhaus+ThreatFox grouped: max(0.80, 0.70) = 0.80 → 80%, effectiveVoters=1 → cap 60
		{"urlhaus+threatfox (grouped abuse.ch)", []string{model.SourceURLhaus, model.SourceThreatFox}, 2, 60},
		// Feodo+ThreatFox: same abuse.ch group → max(0.85,0.70)=0.85, 1 effective voter → cap 60
		{"feodo+threatfox", []string{model.SourceFeodo, model.SourceThreatFox}, 2, 60},
		// Feodo+URLhaus: same abuse.ch group → max(0.85,0.80)=0.85, 1 effective voter → cap 60
		{"feodo+urlhaus", []string{model.SourceFeodo, model.SourceURLhaus}, 2, 60},
		// URLhaus+OTX: 2 effective voters → 1-(0.20*0.65) = 87%
		{"urlhaus+otx", []string{model.SourceURLhaus, model.SourceOTX}, 2, 87},
		// URLhaus+ThreatFox+OTX: group(0.80)+OTX(0.35) → 2 effective voters → 87%
		{"urlhaus+threatfox+otx", []string{model.SourceURLhaus, model.SourceThreatFox, model.SourceOTX}, 3, 87},
		// Feodo+URLhaus+ThreatFox: all abuse.ch group → max(0.85)=0.85, 1 effective voter → cap 60
		{"feodo+urlhaus+threatfox", []string{model.SourceFeodo, model.SourceURLhaus, model.SourceThreatFox}, 3, 60},
		// All four: abuse.ch group max(0.85)+OTX(0.35) → 2 effective → 1-(0.15*0.65) = 90%
		{"all four sources", []string{model.SourceFeodo, model.SourceURLhaus, model.SourceThreatFox, model.SourceOTX}, 4, 90},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			threat := scoring.ScoreResult{Voters: tc.voters, Yes: tc.yes}
			got := scoring.Calculate(model.Malicious, threat, scoring.ScoreResult{})
			if got != tc.want {
				t.Errorf("Calculate(malicious, voters=%v) = %d, want %d",
					tc.voters, got, tc.want)
			}
		})
	}
}

// --- Confidence: benign (noisy-OR on FP signals) ---

func TestCalculateBenign(t *testing.T) {
	tests := []struct {
		name   string
		voters []string
		yes    int
		want   int
	}{
		{"no sources", nil, 0, 0},
		// Tranco Top1M only: r=0.50 → 50%, effectiveVoters=1 but below cap
		{"tranco top1m only", []string{string(sources.SignalTrancoTop1M)}, 1, 50},
		// Tranco Top100k (grouped with Top1M): max(0.50,0.90)=0.90 → 90%, effectiveVoters=1 → cap 60
		{"tranco top100k", []string{string(sources.SignalTrancoTop1M), string(sources.SignalTrancoTop100k)}, 1, 60},
		// Tranco + Tor (2 effective voters): group(0.90)+tor(0.30) → 1-(0.10*0.70) = 93%
		{"tranco+tor", []string{string(sources.SignalTrancoTop1M), string(sources.SignalTrancoTop100k), string(sources.SignalTorExit)}, 2, 93},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fp := scoring.ScoreResult{Voters: tc.voters, Yes: tc.yes}
			got := scoring.Calculate(model.Benign, scoring.ScoreResult{}, fp)
			if got != tc.want {
				t.Errorf("Calculate(benign, voters=%v) = %d, want %d",
					tc.voters, got, tc.want)
			}
		})
	}
}

// --- Confidence: suspicious (noisy-OR × 0.5 scaling) ---

func TestCalculateSuspicious(t *testing.T) {
	tests := []struct {
		name   string
		voters []string
		want   int
	}{
		{"no sources", nil, 0},
		// OTX alone: r=0.35 → 35% × 0.5 = 18 (rounded)
		{"otx alone", []string{model.SourceOTX}, 18},
		// URLhaus alone: r=0.80 → 80% × 0.5 = 40
		{"urlhaus alone", []string{model.SourceURLhaus}, 40},
		// Feodo alone: r=0.85 → 85% × 0.5 = 43 (rounded)
		{"feodo alone", []string{model.SourceFeodo}, 43},
		// ThreatFox alone: r=0.70 → 70% × 0.5 = 35
		{"threatfox alone", []string{model.SourceThreatFox}, 35},
		// URLhaus+ThreatFox grouped: 80% × 0.5 = 40
		{"urlhaus+threatfox grouped", []string{model.SourceURLhaus, model.SourceThreatFox}, 40},
		// URLhaus+OTX: 87% × 0.5 = 44 (rounded)
		{"urlhaus+otx", []string{model.SourceURLhaus, model.SourceOTX}, 44},
		// ThreatFox+OTX: (1-0.30*0.65)=0.805 * 0.5 * 100 = 40.25 → 40
		{"threatfox+otx", []string{model.SourceThreatFox, model.SourceOTX}, 40},
		// All four: abuse.ch group(0.85)+OTX(0.35) → 90% × 0.5 = 45
		{"all four capped", []string{model.SourceFeodo, model.SourceURLhaus, model.SourceThreatFox, model.SourceOTX}, 45},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			threat := scoring.ScoreResult{Voters: tc.voters}
			got := scoring.Calculate(model.Suspicious, threat, scoring.ScoreResult{})
			if got != tc.want {
				t.Errorf("Calculate(suspicious, voters=%v) = %d, want %d",
					tc.voters, got, tc.want)
			}
		})
	}
}

func TestSuspiciousPreservesOrdering(t *testing.T) {
	feodo := scoring.ScoreResult{Voters: []string{model.SourceFeodo}}
	urlhaus := scoring.ScoreResult{Voters: []string{model.SourceURLhaus}}
	threatfox := scoring.ScoreResult{Voters: []string{model.SourceThreatFox}}

	cFeodo := scoring.Calculate(model.Suspicious, feodo, scoring.ScoreResult{})
	cURLhaus := scoring.Calculate(model.Suspicious, urlhaus, scoring.ScoreResult{})
	cThreatFox := scoring.Calculate(model.Suspicious, threatfox, scoring.ScoreResult{})

	if cFeodo <= cURLhaus {
		t.Errorf("Feodo (%d) should > URLhaus (%d)", cFeodo, cURLhaus)
	}
	if cURLhaus <= cThreatFox {
		t.Errorf("URLhaus (%d) should > ThreatFox (%d)", cURLhaus, cThreatFox)
	}
}

func TestSuspiciousNeverReaches50(t *testing.T) {
	combos := [][]string{
		{model.SourceOTX},
		{model.SourceFeodo},
		{model.SourceURLhaus, model.SourceThreatFox},
		{model.SourceFeodo, model.SourceURLhaus, model.SourceThreatFox, model.SourceOTX},
	}
	for _, voters := range combos {
		threat := scoring.ScoreResult{Voters: voters}
		got := scoring.Calculate(model.Suspicious, threat, scoring.ScoreResult{})
		if got >= 50 {
			t.Errorf("suspicious voters=%v = %d, should be < 50",
				voters, got)
		}
	}
}

// --- Confidence: unknown (always 0) ---

func TestCalculateUnknown(t *testing.T) {
	tests := []struct {
		name   string
		voters []string
	}{
		{"no sources at all", nil},
		{"otx alone", []string{model.SourceOTX}},
		{"feodo alone", []string{model.SourceFeodo}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			threat := scoring.ScoreResult{Voters: tc.voters}
			got := scoring.Calculate(model.Unknown, threat, scoring.ScoreResult{})
			if got != 0 {
				t.Errorf("Calculate(unknown, voters=%v) = %d, want 0", tc.voters, got)
			}
		})
	}
}

// --- Weight integrity ---

func TestThreatWeightsSumToMax(t *testing.T) {
	sum := scoring.ThreatWeightURLhaus + scoring.ThreatWeightThreatFox +
		scoring.ThreatWeightOTX + scoring.ThreatWeightFeodo
	if sum != scoring.ThreatMaxTotal {
		t.Errorf("threat weights sum to %d, want ThreatMaxTotal (%d)",
			sum, scoring.ThreatMaxTotal)
	}
}

func TestFPWeightsSumToMax(t *testing.T) {
	sum := scoring.FPWeightTrancoTop1M + scoring.FPWeightTrancoTop100kBonus +
		scoring.FPWeightTor
	if sum != scoring.FPMaxTotal {
		t.Errorf("FP weights sum to %d, want FPMaxTotal (%d)",
			sum, scoring.FPMaxTotal)
	}
}

// --- Anchor gate property ---

func TestAnchorGateProperty(t *testing.T) {
	// Without a fresh anchor no score, however high, yields malicious.
	for score := 0; score <= 100; score++ {
		if v := scoring.Decide(score, 0, false, false); v == model.Malicious {
			t.Fatalf("Decide(%d, 0, noAnchor) = malicious; anchor gate is broken", score)
		}
		if v := scoring.Decide(score, 0, true, false); v == model.Malicious {
			t.Fatalf("Decide(%d, 0, staleAnchor) = malicious; fresh gate is broken", score)
		}
	}
	// With a fresh anchor and no FP veto, any score is malicious.
	for score := 0; score <= 100; score++ {
		if v := scoring.Decide(score, 0, true, true); v != model.Malicious {
			t.Fatalf("Decide(%d, 0, freshAnchor) = %v, want malicious (no score threshold)", score, v)
		}
	}
}

// --- Suspicious floor property ---

func TestSuspiciousFloorProperty(t *testing.T) {
	for _, tc := range []struct {
		name   string
		weight int
	}{
		{"URLhaus", scoring.ThreatWeightURLhaus},
		{"Feodo", scoring.ThreatWeightFeodo},
		{"ThreatFox", scoring.ThreatWeightThreatFox},
	} {
		if tc.weight < scoring.ThreatSuspiciousThreshold {
			t.Errorf("%s weight %d < suspicious threshold %d",
				tc.name, tc.weight, scoring.ThreatSuspiciousThreshold)
		}
	}

	if scoring.ThreatWeightOTX >= scoring.ThreatSuspiciousThreshold {
		t.Errorf("OTX weight %d >= suspicious threshold %d; noisy source should stay unknown",
			scoring.ThreatWeightOTX, scoring.ThreatSuspiciousThreshold)
	}
}

// --- FP veto property ---

func TestFPVetoProperty(t *testing.T) {
	// Top 1M alone (FP=30) cannot veto malicious
	if scoring.FPWeightTrancoTop1M >= scoring.FPVetoThreshold {
		t.Errorf("Top1M alone (%d) can veto malicious (threshold %d); only Top100k should",
			scoring.FPWeightTrancoTop1M, scoring.FPVetoThreshold)
	}

	// Top 100k (FP=60) can veto
	top100k := scoring.FPWeightTrancoTop1M + scoring.FPWeightTrancoTop100kBonus
	if top100k < scoring.FPVetoThreshold {
		t.Errorf("Top100k (%d) can't veto malicious (threshold %d)",
			top100k, scoring.FPVetoThreshold)
	}

	// A compromised Top 1M site with 3 threat sources stays malicious
	v := scoring.Decide(85, 30, true, true)
	if v != model.Malicious {
		t.Errorf("Decide(85, 30, freshAnchor) = %v, want malicious (Top1M can't veto)", v)
	}

	// A Top 100k site with the same threat stays suspicious
	v = scoring.Decide(85, 60, true, true)
	if v != model.Suspicious {
		t.Errorf("Decide(85, 60, freshAnchor) = %v, want suspicious (Top100k vetoes)", v)
	}
}

// --- Threat evidence blocks benign ---

func TestThreatEvidenceBlocksBenign(t *testing.T) {
	v := scoring.Decide(35, 60, true, true)
	if v == model.Benign {
		t.Error("URLhaus(35) + Tranco Top100k(60) should not be benign")
	}
	if v != model.Suspicious {
		t.Errorf("URLhaus(35) + Tranco Top100k(60) = %v, want suspicious", v)
	}
}

func TestConfidenceCapsDifferByVerdict(t *testing.T) {
	threat := scoring.ScoreResult{Voters: []string{model.SourceFeodo}, Yes: 1}
	// Malicious: single effective voter cap → 60
	if got := scoring.Calculate(model.Malicious, threat, scoring.ScoreResult{}); got != 60 {
		t.Errorf("malicious single-source = %d, want 60 (single-source cap)", got)
	}
	// Suspicious: 85 × 0.5 = 43
	if got := scoring.Calculate(model.Suspicious, threat, scoring.ScoreResult{}); got != 43 {
		t.Errorf("suspicious single-source = %d, want 43 (noisyOR × 0.5)", got)
	}
	// Unknown: always 0
	if got := scoring.Calculate(model.Unknown, threat, scoring.ScoreResult{}); got != 0 {
		t.Errorf("unknown = %d, want 0", got)
	}
}

func TestBenignReachabilityByIOCType(t *testing.T) {
	domainMax := scoring.FPWeightTrancoTop1M + scoring.FPWeightTrancoTop100kBonus

	if domainMax < scoring.FPBenignThreshold {
		t.Errorf("domain max FP %d < benign threshold %d; Top100k domains should reach benign",
			domainMax, scoring.FPBenignThreshold)
	}

	if scoring.FPWeightTrancoTop1M >= scoring.FPBenignThreshold {
		t.Errorf("Top1M alone (%d) reaches benign threshold %d; only Top100k should",
			scoring.FPWeightTrancoTop1M, scoring.FPBenignThreshold)
	}

	for _, tc := range []struct {
		name string
		max  int
	}{
		{"ip (no FP sources)", 0},
		{"hash (no FP sources)", 0},
	} {
		if tc.max >= scoring.FPBenignThreshold {
			t.Errorf("%s: max FP score %d >= benign threshold %d",
				tc.name, tc.max, scoring.FPBenignThreshold)
		}
	}
}

// --- CTI doctrine regression: cloud hosting does NOT reduce threat ---

func TestCloudHostedMalwareStaysMalicious(t *testing.T) {
	threatEvs := []sources.ThreatEvidence{
		{Source: model.SourceFeodo, Status: model.StatusOk, MalwareFamily: "Emotet"},
	}
	fpEvs := []sources.FPEvidence{}

	threat := scoring.ThreatScore(threatEvs, nil)
	fp := scoring.FPScore(fpEvs)

	if threat.Score != scoring.ThreatWeightFeodo {
		t.Errorf("threat score = %d, want %d (Feodo weight)", threat.Score, scoring.ThreatWeightFeodo)
	}

	verdict := scoring.Decide(threat.Score, fp.Score, threat.HasAnchor, threat.HasFreshAnchor)
	if verdict != model.Malicious {
		t.Errorf("single-anchor verdict = %v, want malicious (fresh Feodo anchor, no score threshold)", verdict)
	}
	if c := scoring.Calculate(verdict, threat, fp); c != 60 {
		t.Errorf("single-anchor confidence = %d, want 60 (single-group cap)", c)
	}

	threatEvs = append(threatEvs, sources.ThreatEvidence{
		Source: model.SourceThreatFox, Status: model.StatusOk, MalwareFamily: "Cobalt Strike",
	})
	threat = scoring.ThreatScore(threatEvs, nil)
	verdict = scoring.Decide(threat.Score, fp.Score, threat.HasAnchor, threat.HasFreshAnchor)

	if verdict != model.Malicious {
		t.Errorf("Feodo+ThreatFox verdict = %v, want malicious", verdict)
	}
}

// --- Anchor gate: secondary-only sources must NOT reach malicious ---

func TestSecondaryOnlyCannotReachMalicious(t *testing.T) {
	threatEvs := []sources.ThreatEvidence{
		{Source: model.SourceThreatFox, Status: model.StatusOk, MalwareFamily: "Cobalt Strike"},
		{Source: model.SourceOTX, Status: model.StatusOk, MalwareFamily: "botnet"},
	}
	threat := scoring.ThreatScore(threatEvs, nil)
	if threat.HasAnchor {
		t.Fatal("ThreatFox+OTX should not set HasAnchor")
	}

	verdict := scoring.Decide(threat.Score, 0, threat.HasAnchor, threat.HasFreshAnchor)
	if verdict == model.Malicious {
		t.Errorf("ThreatFox+OTX (score=%d) without anchor got malicious; want suspicious",
			threat.Score)
	}
	if verdict != model.Suspicious {
		t.Errorf("ThreatFox+OTX = %d, verdict = %v, want suspicious", threat.Score, verdict)
	}
}

// --- ThreatFox anchor upgrade: weight 40, reliability 0.85 ---

func TestThreatFoxAnchorWeight(t *testing.T) {
	threatEvs := []sources.ThreatEvidence{
		{Source: model.SourceThreatFox, Status: model.StatusOk, MalwareFamily: "Cobalt Strike", Anchor: true},
		{Source: model.SourceOTX, Status: model.StatusOk, MalwareFamily: "botnet"},
	}
	threat := scoring.ThreatScore(threatEvs, nil)

	wantScore := scoring.ThreatWeightThreatFoxAnchor + scoring.ThreatWeightOTX // 40+20=60
	if threat.Score != wantScore {
		t.Errorf("ThreatFox-anchor+OTX score = %d, want %d", threat.Score, wantScore)
	}
	if !threat.HasAnchor {
		t.Error("ThreatFox with Anchor=true should set HasAnchor")
	}
	if !threat.HasFreshAnchor {
		t.Error("ThreatFox with Anchor=true (no decay) should set HasFreshAnchor")
	}

	verdict := scoring.Decide(threat.Score, 0, threat.HasAnchor, threat.HasFreshAnchor)
	if verdict != model.Malicious {
		t.Errorf("ThreatFox-anchor+OTX verdict = %v, want malicious", verdict)
	}
}

func TestThreatFoxAnchorReliability(t *testing.T) {
	// ThreatFox-anchor alone: r=0.85 → cap 60 (single effective voter)
	threat := scoring.ScoreResult{
		Voters:               []string{model.SourceThreatFox},
		ReliabilityOverrides: map[string]float64{model.SourceThreatFox: scoring.ThreatFoxAnchorReliability},
	}
	got := scoring.Calculate(model.Malicious, threat, scoring.ScoreResult{})
	if got != 60 {
		t.Errorf("ThreatFox-anchor alone = %d, want 60 (single-source cap)", got)
	}

	// URLhaus + ThreatFox-anchor: grouped max(0.80, 0.85)=0.85, 1 effective voter → cap 60
	threat = scoring.ScoreResult{
		Voters:               []string{model.SourceURLhaus, model.SourceThreatFox},
		ReliabilityOverrides: map[string]float64{model.SourceThreatFox: scoring.ThreatFoxAnchorReliability},
	}
	got = scoring.Calculate(model.Malicious, threat, scoring.ScoreResult{})
	if got != 60 {
		t.Errorf("URLhaus+ThreatFox-anchor grouped = %d, want 60 (single effective voter cap)", got)
	}

	// Feodo + ThreatFox-anchor: same abuse.ch group → max(0.85, 0.85)=0.85, 1 effective → cap 60
	threat = scoring.ScoreResult{
		Voters:               []string{model.SourceFeodo, model.SourceThreatFox},
		ReliabilityOverrides: map[string]float64{model.SourceThreatFox: scoring.ThreatFoxAnchorReliability},
	}
	got = scoring.Calculate(model.Malicious, threat, scoring.ScoreResult{})
	if got != 60 {
		t.Errorf("Feodo+ThreatFox-anchor = %d, want 60 (same group, single effective voter cap)", got)
	}

	// Feodo + ThreatFox-anchor + OTX: abuse.ch group(0.85) + OTX(0.35), 2 effective → 1-(0.15*0.65) = 90%
	threat = scoring.ScoreResult{
		Voters:               []string{model.SourceFeodo, model.SourceThreatFox, model.SourceOTX},
		ReliabilityOverrides: map[string]float64{model.SourceThreatFox: scoring.ThreatFoxAnchorReliability},
	}
	got = scoring.Calculate(model.Malicious, threat, scoring.ScoreResult{})
	if got != 90 {
		t.Errorf("Feodo+ThreatFox-anchor+OTX = %d, want 90", got)
	}
}

func TestThreatFoxWithoutAnchorUnchanged(t *testing.T) {
	threatEvs := []sources.ThreatEvidence{
		{Source: model.SourceThreatFox, Status: model.StatusOk, MalwareFamily: "Cobalt Strike", Anchor: false},
	}
	threat := scoring.ThreatScore(threatEvs, nil)
	if threat.Score != scoring.ThreatWeightThreatFox {
		t.Errorf("non-anchor ThreatFox weight = %d, want %d", threat.Score, scoring.ThreatWeightThreatFox)
	}
	if threat.ReliabilityOverrides != nil {
		t.Error("non-anchor ThreatFox should not set ReliabilityOverrides")
	}
}

// --- Noisy-OR correlation: grouped sources don't inflate confidence ---

func TestCorrelatedSourcesDontInflate(t *testing.T) {
	grouped := scoring.ScoreResult{
		Voters: []string{model.SourceURLhaus, model.SourceThreatFox},
		Yes:    2,
	}
	got := scoring.Calculate(model.Malicious, grouped, scoring.ScoreResult{})
	if got != 60 {
		t.Errorf("grouped abuse.ch confidence = %d, want 60 (single effective voter → cap)", got)
	}

	// Adding Feodo (same group) does NOT increase confidence
	withFeodo := scoring.ScoreResult{
		Voters: []string{model.SourceURLhaus, model.SourceThreatFox, model.SourceFeodo},
		Yes:    3,
	}
	got2 := scoring.Calculate(model.Malicious, withFeodo, scoring.ScoreResult{})
	if got2 != 60 {
		t.Errorf("all abuse.ch sources = %d, want 60 (same group → cap)", got2)
	}

	// Adding OTX (independent) DOES increase confidence
	withOTX := scoring.ScoreResult{
		Voters: []string{model.SourceURLhaus, model.SourceThreatFox, model.SourceOTX},
		Yes:    3,
	}
	got3 := scoring.Calculate(model.Malicious, withOTX, scoring.ScoreResult{})
	if got3 <= got {
		t.Errorf("adding independent OTX didn't increase confidence: %d vs %d", got3, got)
	}
}

// --- Noisy-OR: silence is not evidence against ---

func TestSilenceDoesNotDilute(t *testing.T) {
	feodoOnly := scoring.ScoreResult{
		Voters: []string{model.SourceFeodo},
		Yes:    1,
	}
	c := scoring.Calculate(model.Malicious, feodoOnly, scoring.ScoreResult{})
	if c != 60 {
		t.Errorf("feodo alone = %d, want 60 (single effective voter cap)", c)
	}
}
