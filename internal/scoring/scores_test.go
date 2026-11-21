package scoring_test

import (
	"testing"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/scoring"
	"github.com/DonobanR/kagemusha/internal/sources"
)

func TestThreatScore(t *testing.T) {
	tests := []struct {
		name string
		evs  []sources.ThreatEvidence
		want scoring.ScoreResult
	}{
		{
			"urlhaus ok, threatfox not listed, otx error",
			[]sources.ThreatEvidence{
				{Source: model.SourceURLhaus, Status: model.StatusOk},
				{Source: model.SourceThreatFox, Status: model.StatusNotListed},
				{Source: model.SourceOTX, Status: model.StatusError},
			},
			scoring.ScoreResult{
				Score: 35, Yes: 1, Total: 2, HasAnchor: true, HasFreshAnchor: true,
				Voters: []string{model.SourceURLhaus},
			},
		},
		{
			"all three listed",
			[]sources.ThreatEvidence{
				{Source: model.SourceURLhaus, Status: model.StatusOk},
				{Source: model.SourceThreatFox, Status: model.StatusOk},
				{Source: model.SourceOTX, Status: model.StatusOk},
			},
			scoring.ScoreResult{
				Score: 85, Yes: 3, Total: 3, HasAnchor: true, HasFreshAnchor: true,
				Voters: []string{model.SourceURLhaus, model.SourceThreatFox, model.SourceOTX},
			},
		},
		{
			"none listed, all responded",
			[]sources.ThreatEvidence{
				{Source: model.SourceURLhaus, Status: model.StatusNotListed},
				{Source: model.SourceThreatFox, Status: model.StatusNotListed},
				{Source: model.SourceOTX, Status: model.StatusNotListed},
			},
			scoring.ScoreResult{
				Score: 0, Yes: 0, Total: 3,
			},
		},
		{
			"all errored",
			[]sources.ThreatEvidence{
				{Source: model.SourceURLhaus, Status: model.StatusError},
				{Source: model.SourceThreatFox, Status: model.StatusTimeout},
				{Source: model.SourceOTX, Status: model.StatusRateLimited},
			},
			scoring.ScoreResult{},
		},
		{
			"hash: only urlhaus applies",
			[]sources.ThreatEvidence{
				{Source: model.SourceURLhaus, Status: model.StatusOk},
			},
			scoring.ScoreResult{
				Score: 35, Yes: 1, Total: 1, HasAnchor: true, HasFreshAnchor: true,
				Voters: []string{model.SourceURLhaus},
			},
		},
		{
			"empty evidence",
			nil,
			scoring.ScoreResult{},
		},
		{
			"urlhaus + otx = 55 (below malicious threshold)",
			[]sources.ThreatEvidence{
				{Source: model.SourceURLhaus, Status: model.StatusOk},
				{Source: model.SourceOTX, Status: model.StatusOk},
				{Source: model.SourceThreatFox, Status: model.StatusNotListed},
			},
			scoring.ScoreResult{
				Score: 55, Yes: 2, Total: 3, HasAnchor: true, HasFreshAnchor: true,
				Voters: []string{model.SourceURLhaus, model.SourceOTX},
			},
		},
		{
			"feodo sets anchor",
			[]sources.ThreatEvidence{
				{Source: model.SourceFeodo, Status: model.StatusOk, MalwareFamily: "Emotet"},
				{Source: model.SourceOTX, Status: model.StatusNotListed},
			},
			scoring.ScoreResult{
				Score: 40, Yes: 1, Total: 2, HasAnchor: true, HasFreshAnchor: true,
				Voters: []string{model.SourceFeodo},
			},
		},
		{
			"secondary only: no anchor",
			[]sources.ThreatEvidence{
				{Source: model.SourceThreatFox, Status: model.StatusOk},
				{Source: model.SourceOTX, Status: model.StatusOk},
			},
			scoring.ScoreResult{
				Score: 50, Yes: 2, Total: 2,
				Voters: []string{model.SourceThreatFox, model.SourceOTX},
			},
		},
		{
			"threatfox entry-level anchor",
			[]sources.ThreatEvidence{
				{Source: model.SourceThreatFox, Status: model.StatusOk, Anchor: true},
				{Source: model.SourceOTX, Status: model.StatusOk},
			},
			scoring.ScoreResult{
				Score: 60, Yes: 2, Total: 2, HasAnchor: true, HasFreshAnchor: true,
				Voters: []string{model.SourceThreatFox, model.SourceOTX},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := scoring.ThreatScore(tc.evs, nil)
			if got.Score != tc.want.Score || got.Yes != tc.want.Yes ||
				got.Total != tc.want.Total || got.HasAnchor != tc.want.HasAnchor ||
				got.HasFreshAnchor != tc.want.HasFreshAnchor {
				t.Errorf("ThreatScore fields = {Score:%d Yes:%d Total:%d Anchor:%v Fresh:%v}, want {Score:%d Yes:%d Total:%d Anchor:%v Fresh:%v}",
					got.Score, got.Yes, got.Total, got.HasAnchor, got.HasFreshAnchor,
					tc.want.Score, tc.want.Yes, tc.want.Total, tc.want.HasAnchor, tc.want.HasFreshAnchor)
			}
			if len(got.Voters) != len(tc.want.Voters) {
				t.Errorf("Voters = %v, want %v", got.Voters, tc.want.Voters)
			} else {
				for i, v := range got.Voters {
					if v != tc.want.Voters[i] {
						t.Errorf("Voters[%d] = %q, want %q", i, v, tc.want.Voters[i])
					}
				}
			}
		})
	}
}

func TestFPScore(t *testing.T) {
	tests := []struct {
		name string
		evs  []sources.FPEvidence
		want scoring.ScoreResult
	}{
		{
			"tranco top1m + top100k",
			[]sources.FPEvidence{
				{Source: model.SourceTranco, Status: model.StatusOk,
					Signals: []sources.FPSignal{sources.SignalTrancoTop1M, sources.SignalTrancoTop100k}},
			},
			scoring.ScoreResult{
				Score: 60, Yes: 1, Total: 1,
				Voters: []string{string(sources.SignalTrancoTop1M), string(sources.SignalTrancoTop100k)},
			},
		},
		{
			"tranco checked but no signals",
			[]sources.FPEvidence{
				{Source: model.SourceTranco, Status: model.StatusOk, Signals: nil},
			},
			scoring.ScoreResult{
				Score: 0, Yes: 0, Total: 1,
			},
		},
		{
			"tranco + tor",
			[]sources.FPEvidence{
				{Source: model.SourceTranco, Status: model.StatusOk,
					Signals: []sources.FPSignal{sources.SignalTrancoTop1M, sources.SignalTrancoTop100k}},
				{Source: model.SourceTor, Status: model.StatusOk,
					Signals: []sources.FPSignal{sources.SignalTorExit}},
			},
			scoring.ScoreResult{
				Score: 70, Yes: 2, Total: 2,
				Voters: []string{
					string(sources.SignalTrancoTop1M),
					string(sources.SignalTrancoTop100k),
					string(sources.SignalTorExit),
				},
			},
		},
		{
			"empty evidence",
			nil,
			scoring.ScoreResult{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := scoring.FPScore(tc.evs)
			if got.Score != tc.want.Score || got.Yes != tc.want.Yes || got.Total != tc.want.Total {
				t.Errorf("FPScore fields = {Score:%d Yes:%d Total:%d}, want {Score:%d Yes:%d Total:%d}",
					got.Score, got.Yes, got.Total,
					tc.want.Score, tc.want.Yes, tc.want.Total)
			}
			if len(got.Voters) != len(tc.want.Voters) {
				t.Errorf("Voters = %v, want %v", got.Voters, tc.want.Voters)
			} else {
				for i, v := range got.Voters {
					if v != tc.want.Voters[i] {
						t.Errorf("Voters[%d] = %q, want %q", i, v, tc.want.Voters[i])
					}
				}
			}
		})
	}
}

func TestIntegrationHashSingleSource(t *testing.T) {
	threat := scoring.ThreatScore([]sources.ThreatEvidence{
		{Source: model.SourceURLhaus, Status: model.StatusOk},
	}, nil)
	fp := scoring.FPScore(nil)

	verdict := scoring.Decide(threat.Score, fp.Score, threat.HasAnchor, threat.HasFreshAnchor)
	if verdict != model.Malicious {
		t.Errorf("verdict = %v, want malicious (URLhaus is an anchor; hash has no decay → fresh)", verdict)
	}

	// Malicious: noisyOR(URLhaus r=0.80) = 80%, single group cap → 60
	confidence := scoring.Calculate(verdict, threat, fp)
	if confidence != 60 {
		t.Errorf("confidence = %d, want 60 (single-group cap)", confidence)
	}
}

// Integration: URLhaus + ThreatFox → Malicious, grouped noisy-OR.
func TestIntegrationTwoSourcesMalicious(t *testing.T) {
	threat := scoring.ThreatScore([]sources.ThreatEvidence{
		{Source: model.SourceURLhaus, Status: model.StatusOk},
		{Source: model.SourceThreatFox, Status: model.StatusOk},
		{Source: model.SourceOTX, Status: model.StatusNotListed},
	}, nil)
	fp := scoring.FPScore(nil)

	verdict := scoring.Decide(threat.Score, fp.Score, threat.HasAnchor, threat.HasFreshAnchor)
	if verdict != model.Malicious {
		t.Errorf("verdict = %v, want malicious (threat=65, anchor=true)", verdict)
	}

	// Grouped noisy-OR: abuse.ch group max(0.80, 0.70) = 0.80 → 80%,
	// but effectiveVoters=1 (one group) → single-source cap → 60%
	confidence := scoring.Calculate(verdict, threat, fp)
	if confidence != 60 {
		t.Errorf("confidence = %d, want 60 (grouped → single effective voter → cap)", confidence)
	}
}
