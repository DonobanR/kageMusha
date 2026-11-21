package cli_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/DonobanR/kagemusha/internal/cli"
	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/ratelimit"
	"github.com/DonobanR/kagemusha/internal/sources"
	"github.com/DonobanR/kagemusha/internal/sources/fake"
	"github.com/DonobanR/kagemusha/internal/sources/threatfox"
	"github.com/DonobanR/kagemusha/internal/sources/tranco"
	"github.com/DonobanR/kagemusha/internal/sources/urlhaus"
)

func TestIntegrationURLhausToJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		host := r.FormValue("host")
		md5 := r.FormValue("md5_hash")

		switch {
		case host == "evil.com":
			w.Write([]byte(`{
				"query_status": "ok",
				"url_count": "1",
				"urls": [{"threat": "malware_download", "tags": ["emotet"]}]
			}`))
		case host == "google.com":
			w.Write([]byte(`{"query_status": "no_results"}`))
		case md5 == "d41d8cd98f00b204e9800998ecf8427e":
			w.Write([]byte(`{
				"query_status": "ok",
				"signature": "Heodo",
				"file_type": "exe"
			}`))
		default:
			w.Write([]byte(`{"query_status": "no_results"}`))
		}
	}))
	defer srv.Close()

	threatSrcs := []sources.ThreatSource{
		urlhaus.NewWithBase(srv.URL, "test-key"),
	}

	results, err := cli.RunScan(context.Background(), cli.ScanOptions{
		RawIOCs:       []string{"evil.com", "google.com", "d41d8cd98f00b204e9800998ecf8427e"},
		ThreatSources: threatSrcs,
		FPSources:     nil,
	})
	if err != nil {
		t.Fatalf("RunScan error: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}

	// evil.com: URLhaus listed but the mock response carries no date, so the
	// anchor cannot be proven fresh (no decay entry) → suspicious, not malicious.
	// Confidence: noisyOR 80% × 0.5 = 40. (Dated fresh anchors → malicious: see
	// TestIntegrationURLhausOnlyFreshAnchorMalicious.)
	assertResult(t, results[0], "evil.com", model.TypeDomain, model.Suspicious, 40)
	if results[0].Sources[0].Status != model.StatusOk {
		t.Errorf("evil.com source status = %q, want ok", results[0].Sources[0].Status)
	}

	// google.com: URLhaus not listed → threat=0, fp=0 → unknown, confidence=0
	assertResult(t, results[1], "google.com", model.TypeDomain, model.Unknown, 0)
	if results[1].Sources[0].Status != model.StatusNotListed {
		t.Errorf("google.com source status = %q, want not_listed", results[1].Sources[0].Status)
	}

	// MD5 hash: URLhaus listed (anchor; hashes have no decay → fresh) → malicious, confidence capped at 60.
	assertResult(t, results[2], "d41d8cd98f00b204e9800998ecf8427e", model.TypeHashMD5, model.Malicious, 60)

	// Verify JSON structure has all expected fields.
	data, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw []map[string]interface{}
	json.Unmarshal(data, &raw)
	for i, r := range raw {
		for _, field := range []string{"target", "type", "verdict", "confidence", "reasons", "sources"} {
			if _, ok := r[field]; !ok {
				t.Errorf("result[%d] missing field %q", i, field)
			}
		}
	}
}

func TestIntegrationSingleSourceNeverMalicious(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"query_status": "ok",
			"url_count": "1",
			"urls": [{"threat": "malware_download", "tags": ["emotet"]}]
		}`))
	}))
	defer srv.Close()

	threatSrcs := []sources.ThreatSource{
		urlhaus.NewWithBase(srv.URL, "test-key"),
	}

	results, err := cli.RunScan(context.Background(), cli.ScanOptions{
		RawIOCs:       []string{"evil.com"},
		ThreatSources: threatSrcs,
	})
	if err != nil {
		t.Fatalf("RunScan error: %v", err)
	}

	// URLhaus alone = 35 threat, 0 fp → Suspicious (35 >= 30).
	// This validates the URLhaus gate: no single source reaches malicious.
	if results[0].Verdict != model.Suspicious {
		t.Errorf("verdict = %q, want suspicious (URLhaus alone can't reach malicious)", results[0].Verdict)
	}
}

func TestIntegrationSkipsInvalidIOC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"query_status": "no_results"}`))
	}))
	defer srv.Close()

	threatSrcs := []sources.ThreatSource{
		urlhaus.NewWithBase(srv.URL, "test-key"),
	}

	results, err := cli.RunScan(context.Background(), cli.ScanOptions{
		RawIOCs:       []string{"not-an-ioc!!!", "google.com"},
		ThreatSources: threatSrcs,
	})
	if err != nil {
		t.Fatalf("RunScan error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1 (invalid IOC should be skipped)", len(results))
	}
	if results[0].Target != "google.com" {
		t.Errorf("target = %q, want google.com", results[0].Target)
	}
}

func TestIntegrationURLhausWithTranco(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		host := r.FormValue("host")
		switch host {
		case "google.com":
			w.Write([]byte(`{"query_status": "no_results"}`))
		case "evil-not-in-tranco.test":
			w.Write([]byte(`{
				"query_status": "ok",
				"url_count": "1",
				"urls": [{"threat": "malware_download", "tags": ["emotet"]}]
			}`))
		default:
			w.Write([]byte(`{"query_status": "no_results"}`))
		}
	}))
	defer srv.Close()

	trancoFixture := "../sources/tranco/testdata/top-1m-fixture.csv"

	threatSrcs := []sources.ThreatSource{
		urlhaus.NewWithBase(srv.URL, "test-key"),
	}
	fpSrcs := []sources.FPSource{
		tranco.NewWithPath(trancoFixture, false),
	}

	results, err := cli.RunScan(context.Background(), cli.ScanOptions{
		RawIOCs:       []string{"google.com", "evil-not-in-tranco.test"},
		ThreatSources: threatSrcs,
		FPSources:     fpSrcs,
	})
	if err != nil {
		t.Fatalf("RunScan error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}

	// google.com: URLhaus not_listed (threat=0) + Tranco top 100k (fp=60)
	// Decide(0, 60): threat<60, fp>=60 → Benign.
	// Confidence: noisyOR group max(0.50,0.90)=0.90 → 90%, effectiveVoters=1 → cap 60%.
	assertResult(t, results[0], "google.com", model.TypeDomain, model.Benign, 60)
	if len(results[0].Sources) != 2 {
		t.Fatalf("google.com sources = %d, want 2 (urlhaus + tranco)", len(results[0].Sources))
	}
	trancoSrc := results[0].Sources[1]
	if trancoSrc.Name != model.SourceTranco {
		t.Errorf("source[1] = %q, want tranco", trancoSrc.Name)
	}
	if trancoSrc.Status != model.StatusOk {
		t.Errorf("tranco status = %q, want ok", trancoSrc.Status)
	}
	if trancoSrc.Detail == "" {
		t.Error("tranco detail should contain signal names for google.com")
	}

	// evil-not-in-tranco.test: URLhaus listed (threat=35) + Tranco absent (fp=0)
	// Decide(35, 0): threat>=30 → Suspicious. Confidence: 80×0.5=40.
	assertResult(t, results[1], "evil-not-in-tranco.test", model.TypeDomain, model.Suspicious, 40)
	if len(results[1].Sources) != 2 {
		t.Fatalf("evil sources = %d, want 2", len(results[1].Sources))
	}
}

func TestIntegrationAllInvalidReturnsError(t *testing.T) {
	results, err := cli.RunScan(context.Background(), cli.ScanOptions{
		RawIOCs: []string{"not-valid!!!", "also bad???"},
	})
	if err == nil {
		t.Error("expected error when all IOCs are invalid")
	}
	if results != nil {
		t.Errorf("expected nil results, got %d", len(results))
	}
}

func TestRunScanContextCancelledBeforeIOC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	src := &fake.CancelOnNthThreatSource{
		SourceName: "canceller",
		Limit:      2,
		Cancel:     cancel,
	}

	results, err := cli.RunScan(ctx, cli.ScanOptions{
		RawIOCs:       []string{"a.com", "b.com", "c.com", "d.com", "e.com"},
		ThreatSources: []sources.ThreatSource{src},
		Workers:       1,
	})
	if err != nil {
		t.Fatalf("RunScan error: %v", err)
	}

	// Source cancels ctx on 2nd call. The loop checks ctx.Err() before
	// each IOC, so the 3rd IOC never starts. Exactly 2 results.
	if len(results) != 2 {
		t.Errorf("got %d results, want 2", len(results))
	}
}

func TestRunScanInFlightIOCEmitsTimeout(t *testing.T) {
	src := &fake.BlockingThreatSource{SourceName: "blocker", BlockFor: 10 * time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	results, err := cli.RunScan(ctx, cli.ScanOptions{
		RawIOCs:       []string{"victim.com"},
		ThreatSources: []sources.ThreatSource{src},
	})
	if err != nil {
		t.Fatalf("RunScan error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("got %d results, want 1 (in-flight IOC should be emitted)", len(results))
	}
	if results[0].Sources[0].Status != model.StatusTimeout {
		t.Errorf("source status = %q, want timeout", results[0].Sources[0].Status)
	}
}

func TestIntegrationURLhausPlusThreatFoxReachesMalicious(t *testing.T) {
	// Fixed clock: 2026-11-15. Mock dates are 2026-11-01 (14 days old, within 90-day domain window).
	fixedNow := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixedNow }

	urlhausSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"query_status": "ok",
			"url_count": "1",
			"urls": [{"threat": "malware_download", "tags": ["emotet"], "url_status": "online", "date_added": "2026-11-01 00:00:00 UTC"}]
		}`))
	}))
	defer urlhausSrv.Close()

	threatfoxSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"query_status": "ok",
			"data": [{"ioc": "evil.com", "malware_printable": "Emotet", "threat_type": "botnet_cc", "confidence_level": 75, "reporter": "abuse_ch", "first_seen": "2026-11-01 00:00:00 UTC"}]
		}`))
	}))
	defer threatfoxSrv.Close()

	results, err := cli.RunScan(context.Background(), cli.ScanOptions{
		RawIOCs: []string{"evil.com"},
		Now:     fixedNow,
		ThreatSources: []sources.ThreatSource{
			urlhaus.NewWithBaseClock(urlhausSrv.URL, "test-key", clock),
			threatfox.NewWithBaseClock(threatfoxSrv.URL, "test-key", clock),
		},
	})
	if err != nil {
		t.Fatalf("RunScan error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}

	// URLhaus (35) + ThreatFox anchor (40) = 75 >= 60.
	// Both are anchors (URLhaus by source, ThreatFox by entry: abuse_ch + botnet_cc).
	// Grouped abuse.ch max(0.80, 0.85)=0.85 → 85%, effectiveVoters=1 → cap 60%.
	assertResult(t, results[0], "evil.com", model.TypeDomain, model.Malicious, 60)

	if len(results[0].Sources) != 2 {
		t.Fatalf("sources = %d, want 2", len(results[0].Sources))
	}
	if results[0].Sources[0].Name != model.SourceURLhaus {
		t.Errorf("source[0] = %q, want urlhaus", results[0].Sources[0].Name)
	}
	if results[0].Sources[1].Name != model.SourceThreatFox {
		t.Errorf("source[1] = %q, want threatfox", results[0].Sources[1].Name)
	}
}

func TestIntegrationURLhausOnlyFreshAnchorMalicious(t *testing.T) {
	fixedNow := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixedNow }

	urlhausSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"query_status": "ok",
			"url_count": "1",
			"urls": [{"threat": "malware_download", "tags": ["emotet"], "url_status": "online", "date_added": "2026-11-01 00:00:00 UTC"}]
		}`))
	}))
	defer urlhausSrv.Close()

	threatfoxSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"query_status": "no_result", "data": null}`))
	}))
	defer threatfoxSrv.Close()

	results, err := cli.RunScan(context.Background(), cli.ScanOptions{
		RawIOCs: []string{"evil.com"},
		Now:     fixedNow,
		ThreatSources: []sources.ThreatSource{
			urlhaus.NewWithBaseClock(urlhausSrv.URL, "test-key", clock),
			threatfox.NewWithBase(threatfoxSrv.URL, "test-key"),
		},
	})
	if err != nil {
		t.Fatalf("RunScan error: %v", err)
	}

	// URLhaus is a fresh anchor (date_added 2026-11-01) → malicious regardless of score.
	// Confidence: noisy-OR 80%, single correlation group → capped at 60.
	// ThreatFox silence does NOT dilute (noisy-OR treats it as absence).
	assertResult(t, results[0], "evil.com", model.TypeDomain, model.Malicious, 60)
}

// A fresh anchor on a subdomain of a Top-100k domain must be vetoed via the
// parent-domain Tranco lookup (cdn.discordapp.com → discordapp.com, rank 150
// in the fixture). Without the parent lookup this would be malicious.
func TestRunScanSubdomainOfTop100kVetoed(t *testing.T) {
	fixedNow := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixedNow }

	urlhausSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"query_status": "ok",
			"url_count": "1",
			"urls": [{"threat": "malware_download", "tags": ["x"], "url_status": "online", "date_added": "2026-11-10 00:00:00 UTC"}]
		}`))
	}))
	defer urlhausSrv.Close()

	results, err := cli.RunScan(context.Background(), cli.ScanOptions{
		RawIOCs:       []string{"cdn.discordapp.com"},
		Now:           fixedNow,
		ThreatSources: []sources.ThreatSource{urlhaus.NewWithBaseClock(urlhausSrv.URL, "test-key", clock)},
		FPSources:     []sources.FPSource{tranco.NewWithPath("../sources/tranco/testdata/top-1m-fixture.csv", false)},
	})
	if err != nil {
		t.Fatalf("RunScan error: %v", err)
	}
	if results[0].Verdict == model.Malicious {
		t.Errorf("verdict = malicious, want veto by Tranco parent domain (got FP=%d)", results[0].FPScore)
	}
}

// A popular domain must not come out benign when a threat source failed:
// we cannot know whether URLhaus lists it (round-23: discord.com was
// benign 60% without an abuse.ch key, suspicious with one).
func TestRunScanBenignBecomesUnknownWhenThreatSourceFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	results, err := cli.RunScan(context.Background(), cli.ScanOptions{
		RawIOCs:       []string{"google.com"},
		ThreatSources: []sources.ThreatSource{urlhaus.NewWithBase(srv.URL, "test-key")},
		FPSources:     []sources.FPSource{tranco.NewWithPath("../sources/tranco/testdata/top-1m-fixture.csv", false)},
	})
	if err != nil {
		t.Fatalf("RunScan error: %v", err)
	}
	r := results[0]
	assertResult(t, r, "google.com", model.TypeDomain, model.Unknown, 0)
	if !r.Partial || len(r.FailedSources) != 1 || r.FailedSources[0] != model.SourceURLhaus {
		t.Errorf("partial=%v failed=%v, want partial with urlhaus", r.Partial, r.FailedSources)
	}
	found := false
	for _, rs := range r.Reasons {
		if rs.Code == "incomplete" {
			found = true
		}
	}
	if !found {
		t.Errorf("missing 'incomplete' reason: %+v", r.Reasons)
	}
}

func TestRunScanBuggyThreatSourceReturnsError(t *testing.T) {
	src := &fake.BuggyThreatSource{SourceName: "buggy"}
	_, err := cli.RunScan(context.Background(), cli.ScanOptions{
		RawIOCs:       []string{"test.com"},
		ThreatSources: []sources.ThreatSource{src},
	})
	if err == nil {
		t.Fatal("expected error from buggy source, got nil")
	}
	if got := err.Error(); !strings.Contains(got, "BUG:") || !strings.Contains(got, "buggy") {
		t.Errorf("error = %q, want BUG: prefix with source name", got)
	}
}

func TestRunScanBuggyFPSourceReturnsError(t *testing.T) {
	okThreat := &fake.FailingThreatSource{SourceName: "ok"}
	buggyFP := &fake.BuggyFPSource{SourceName: "buggy-fp"}
	_, err := cli.RunScan(context.Background(), cli.ScanOptions{
		RawIOCs:       []string{"test.com"},
		ThreatSources: []sources.ThreatSource{okThreat},
		FPSources:     []sources.FPSource{buggyFP},
	})
	if err == nil {
		t.Fatal("expected error from buggy FP source, got nil")
	}
	if got := err.Error(); !strings.Contains(got, "BUG:") || !strings.Contains(got, "buggy-fp") {
		t.Errorf("error = %q, want BUG: prefix with source name", got)
	}
}

// --- Concurrency tests ---

func TestBatchConcurrentResultsPreserveOrder(t *testing.T) {
	src := &fake.FailingThreatSource{SourceName: "ok"}
	iocs := []string{"11.11.11.11", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"}

	results, err := cli.RunScan(context.Background(), cli.ScanOptions{
		RawIOCs:       iocs,
		ThreatSources: []sources.ThreatSource{src},
		Workers:       3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 5 {
		t.Fatalf("got %d results, want 5", len(results))
	}
	for i, r := range results {
		if r.Target != iocs[i] {
			t.Errorf("results[%d].Target = %q, want %q", i, r.Target, iocs[i])
		}
	}
}

func TestRateLimiterThrottlesPoolASources(t *testing.T) {
	src := &fake.TimestampThreatSource{SourceName: model.SourceURLhaus}

	limiter := ratelimit.New(100 * time.Millisecond)
	defer limiter.Close()

	results, err := cli.RunScan(context.Background(), cli.ScanOptions{
		RawIOCs:       []string{"11.11.11.11", "2.2.2.2", "3.3.3.3"},
		ThreatSources: []sources.ThreatSource{src},
		Limiters:      map[string]*ratelimit.Bucket{model.SourceURLhaus: limiter},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}

	calls := src.Calls
	if len(calls) != 3 {
		t.Fatalf("got %d calls, want 3", len(calls))
	}

	sort.Slice(calls, func(i, j int) bool { return calls[i].Before(calls[j]) })
	for i := 1; i < len(calls); i++ {
		gap := calls[i].Sub(calls[i-1])
		if gap < 70*time.Millisecond {
			t.Errorf("gap between call %d and %d = %v, want >= 70ms", i, i+1, gap)
		}
	}
}

func TestPoolBSourcesNotThrottled(t *testing.T) {
	poolA := &fake.TimestampThreatSource{SourceName: model.SourceURLhaus}
	poolB := &fake.TimestampThreatSource{SourceName: model.SourceFeodo}

	limiter := ratelimit.New(500 * time.Millisecond)
	defer limiter.Close()

	start := time.Now()
	results, err := cli.RunScan(context.Background(), cli.ScanOptions{
		RawIOCs:       []string{"11.11.11.11", "2.2.2.2"},
		ThreatSources: []sources.ThreatSource{poolA, poolB},
		Limiters:      map[string]*ratelimit.Bucket{model.SourceURLhaus: limiter},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}

	// Pool B calls should all complete within the first token window.
	for i, c := range poolB.Calls {
		elapsed := c.Sub(start)
		if elapsed > 200*time.Millisecond {
			t.Errorf("Pool B call %d at %v from start, want < 200ms", i, elapsed)
		}
	}
}

func TestNoLimiterMeansNoConcurrencyThrottling(t *testing.T) {
	src := &fake.TimestampThreatSource{SourceName: model.SourceURLhaus}

	start := time.Now()
	results, err := cli.RunScan(context.Background(), cli.ScanOptions{
		RawIOCs:       []string{"11.11.11.11", "2.2.2.2", "3.3.3.3"},
		ThreatSources: []sources.ThreatSource{src},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}

	// Without a limiter all calls should complete almost instantly.
	elapsed := time.Since(start)
	if elapsed > 200*time.Millisecond {
		t.Errorf("3 IOCs without limiter took %v, want < 200ms", elapsed)
	}
}

func TestPartialFlagOnSourceFailure(t *testing.T) {
	okSrc := &fake.StubThreatSource{
		SourceName: model.SourceURLhaus,
		Evidence:   sources.ThreatEvidence{Source: model.SourceURLhaus, Status: model.StatusOk, MalwareFamily: "Emotet"},
	}
	failSrc := &fake.StubThreatSource{
		SourceName: model.SourceOTX,
		Evidence:   sources.ThreatEvidence{Source: model.SourceOTX, Status: model.StatusError},
	}

	results, err := cli.RunScan(context.Background(), cli.ScanOptions{
		RawIOCs:       []string{"evil.com"},
		ThreatSources: []sources.ThreatSource{okSrc, failSrc},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if !results[0].Partial {
		t.Error("expected Partial=true when a source fails")
	}
	if len(results[0].FailedSources) != 1 || results[0].FailedSources[0] != model.SourceOTX {
		t.Errorf("FailedSources = %v, want [otx]", results[0].FailedSources)
	}
}

func TestNoPartialWhenAllSourcesSucceed(t *testing.T) {
	src := &fake.StubThreatSource{
		SourceName: model.SourceURLhaus,
		Evidence:   sources.ThreatEvidence{Source: model.SourceURLhaus, Status: model.StatusOk, MalwareFamily: "Emotet"},
	}

	results, err := cli.RunScan(context.Background(), cli.ScanOptions{
		RawIOCs:       []string{"evil.com"},
		ThreatSources: []sources.ThreatSource{src},
	})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Partial {
		t.Error("expected Partial=false when all sources succeed")
	}
}

func assertResult(t *testing.T, r model.Result, target string, typ model.IOCType, verdict model.Verdict, confidence int) {
	t.Helper()
	if r.Target != target {
		t.Errorf("target = %q, want %q", r.Target, target)
	}
	if r.Type != typ {
		t.Errorf("[%s] type = %q, want %q", target, r.Type, typ)
	}
	if r.Verdict != verdict {
		t.Errorf("[%s] verdict = %q, want %q", target, r.Verdict, verdict)
	}
	if r.Confidence != confidence {
		t.Errorf("[%s] confidence = %d, want %d", target, r.Confidence, confidence)
	}
}
