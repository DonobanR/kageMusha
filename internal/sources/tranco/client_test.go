package tranco_test

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/sources"
	"github.com/DonobanR/kagemusha/internal/sources/tranco"
)

func makeZip(t *testing.T, csvContent string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("top-1m.csv")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte(csvContent))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const fixturePath = "testdata/top-1m-fixture.csv"

func TestAppliesToDomainOnly(t *testing.T) {
	c := tranco.NewWithPath(fixturePath, false)
	if !c.AppliesTo(model.TypeDomain) {
		t.Error("expected AppliesTo(domain) = true")
	}
	for _, typ := range []model.IOCType{
		model.TypeIPv4, model.TypeIPv6, model.TypeURL,
		model.TypeHashMD5, model.TypeHashSHA1, model.TypeHashSHA256,
	} {
		if c.AppliesTo(typ) {
			t.Errorf("expected AppliesTo(%s) = false", typ)
		}
	}
}

func TestBugOnUnsupportedType(t *testing.T) {
	c := tranco.NewWithPath(fixturePath, false)
	_, err := c.Check(context.Background(), model.IOC{Value: "1.2.3.4", Type: model.TypeIPv4})
	if err == nil {
		t.Error("expected error for unsupported type")
	}
}

func TestTop100k(t *testing.T) {
	c := tranco.NewWithPath(fixturePath, false)
	ev, err := c.Check(context.Background(), model.IOC{Value: "google.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	assertEvidence(t, ev, model.StatusOk, 2)
	assertHasSignal(t, ev, sources.SignalTrancoTop1M)
	assertHasSignal(t, ev, sources.SignalTrancoTop100k)
}

func TestTop100kBoundary(t *testing.T) {
	c := tranco.NewWithPath(fixturePath, false)

	// Rank 100000 = last rank in top 100k → gets both signals.
	ev, err := c.Check(context.Background(), model.IOC{Value: "last-top100k.example.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	assertEvidence(t, ev, model.StatusOk, 2)
	assertHasSignal(t, ev, sources.SignalTrancoTop100k)

	// Rank 100001 = just outside → only top 1M signal.
	ev, err = c.Check(context.Background(), model.IOC{Value: "just-outside-100k.example.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	assertEvidence(t, ev, model.StatusOk, 1)
	assertHasSignal(t, ev, sources.SignalTrancoTop1M)
	assertNoSignal(t, ev, sources.SignalTrancoTop100k)
}

func TestTop1MNotTop100k(t *testing.T) {
	c := tranco.NewWithPath(fixturePath, false)
	ev, err := c.Check(context.Background(), model.IOC{Value: "deep-in-1m.example.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	assertEvidence(t, ev, model.StatusOk, 1)
	assertHasSignal(t, ev, sources.SignalTrancoTop1M)
	assertNoSignal(t, ev, sources.SignalTrancoTop100k)
}

func TestDomainAbsent(t *testing.T) {
	c := tranco.NewWithPath(fixturePath, false)
	ev, err := c.Check(context.Background(), model.IOC{Value: "evil-phishing.sbs", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	assertEvidence(t, ev, model.StatusOk, 0)
	if ev.Signals == nil {
		t.Error("Signals should be empty slice, not nil (JSON serializes differently)")
	}
}

func TestSubdomainInheritsParentRank(t *testing.T) {
	for _, lowMem := range []bool{false, true} {
		c := tranco.NewWithPath(fixturePath, lowMem)
		// discordapp.com is rank 150 in the fixture; cdn.discordapp.com is not listed.
		ev, err := c.Check(context.Background(), model.IOC{Value: "cdn.discordapp.com", Type: model.TypeDomain})
		if err != nil {
			t.Fatal(err)
		}
		assertEvidence(t, ev, model.StatusOk, 2)
		assertHasSignal(t, ev, sources.SignalTrancoTop1M)
		assertHasSignal(t, ev, sources.SignalTrancoTop100k)

		// Several labels deep still reaches the parent.
		ev, err = c.Check(context.Background(), model.IOC{Value: "a.b.cdn.discordapp.com", Type: model.TypeDomain})
		if err != nil {
			t.Fatal(err)
		}
		assertEvidence(t, ev, model.StatusOk, 2)
	}
}

func TestSubdomainDoesNotInheritFromPublicSuffix(t *testing.T) {
	// github.io and blogspot.com are listed in the fixture but are shared
	// hosting suffixes (Public Suffix List private section): a tenant
	// subdomain must not inherit the platform's reputation.
	for _, lowMem := range []bool{false, true} {
		c := tranco.NewWithPath(fixturePath, lowMem)
		for _, d := range []string{"evil.github.io", "foo.blogspot.com"} {
			ev, err := c.Check(context.Background(), model.IOC{Value: d, Type: model.TypeDomain})
			if err != nil {
				t.Fatal(err)
			}
			assertEvidence(t, ev, model.StatusOk, 0)
		}
	}
}

func TestUnrelatedSuffixSharingDoesNotMatch(t *testing.T) {
	// "notdiscordapp.com" ends with "discordapp.com" as a string but is not a subdomain.
	c := tranco.NewWithPath(fixturePath, false)
	ev, err := c.Check(context.Background(), model.IOC{Value: "notdiscordapp.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	assertEvidence(t, ev, model.StatusOk, 0)
}

// Regression: Check is called from many scan workers at once. Before the
// mutex, the lazy map load raced (found by `go test -race` under WSL).
func TestConcurrentCheckOnFreshClient(t *testing.T) {
	c := tranco.NewWithPath(fixturePath, false)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ev, err := c.Check(context.Background(), model.IOC{Value: "cdn.discordapp.com", Type: model.TypeDomain})
			if err != nil || len(ev.Signals) != 2 {
				t.Errorf("concurrent Check: err=%v signals=%v", err, ev.Signals)
			}
		}()
	}
	wg.Wait()
}

func TestCorruptCSV(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "bad.csv")
	os.WriteFile(path, []byte("not,a,valid\ncsv,file\n"), 0o644)

	c := tranco.NewWithPath(path, false)
	ev, err := c.Check(context.Background(), model.IOC{Value: "google.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt CSV loads but google.com won't be found → StatusOk, no signals.
	assertEvidence(t, ev, model.StatusOk, 0)
}

func TestMissingCSV(t *testing.T) {
	c := tranco.NewWithPath("/nonexistent/path.csv", false)
	ev, err := c.Check(context.Background(), model.IOC{Value: "google.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusError {
		t.Errorf("status = %q, want error", ev.Status)
	}
}

func TestLowMemoryMode(t *testing.T) {
	c := tranco.NewWithPath(fixturePath, true)

	// Top 100k domain
	ev, err := c.Check(context.Background(), model.IOC{Value: "google.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	assertEvidence(t, ev, model.StatusOk, 2)

	// Absent domain
	ev, err = c.Check(context.Background(), model.IOC{Value: "not-here.test", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	assertEvidence(t, ev, model.StatusOk, 0)
}

func TestCaseInsensitive(t *testing.T) {
	c := tranco.NewWithPath(fixturePath, false)
	ev, err := c.Check(context.Background(), model.IOC{Value: "GOOGLE.COM", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	assertEvidence(t, ev, model.StatusOk, 2)
}

func TestCacheListIDSkipsDownload(t *testing.T) {
	tmp := t.TempDir()
	downloadCount := 0
	zipData := makeZip(t, "1,google.com\n2,youtube.com\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/top-1m-id":
			w.Write([]byte("TEST1"))
		case "/top-1m.csv.zip":
			downloadCount++
			w.Write(zipData)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	c := tranco.NewWithBase(srv.URL, tmp, false)

	// First call: no cache → downloads.
	ev, err := c.Check(context.Background(), model.IOC{Value: "google.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %q, want ok", ev.Status)
	}
	if downloadCount != 1 {
		t.Fatalf("expected 1 download, got %d", downloadCount)
	}

	// Second call with fresh client: same list_id → no download.
	c2 := tranco.NewWithBase(srv.URL, tmp, false)
	ev, err = c2.Check(context.Background(), model.IOC{Value: "google.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %q, want ok", ev.Status)
	}
	if downloadCount != 1 {
		t.Errorf("expected no re-download (count still 1), got %d", downloadCount)
	}
}

func TestCacheListIDChangedRedownloads(t *testing.T) {
	tmp := t.TempDir()
	currentID := "V1"
	downloadCount := 0
	zipData := makeZip(t, "1,google.com\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/top-1m-id":
			w.Write([]byte(currentID))
		case "/top-1m.csv.zip":
			downloadCount++
			w.Write(zipData)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	c := tranco.NewWithBase(srv.URL, tmp, false)
	c.Check(context.Background(), model.IOC{Value: "google.com", Type: model.TypeDomain})
	if downloadCount != 1 {
		t.Fatalf("first download: got %d", downloadCount)
	}

	// Change remote list_id → should re-download.
	currentID = "V2"
	c2 := tranco.NewWithBase(srv.URL, tmp, false)
	c2.Check(context.Background(), model.IOC{Value: "google.com", Type: model.TypeDomain})
	if downloadCount != 2 {
		t.Errorf("expected re-download (count 2), got %d", downloadCount)
	}
}

func TestDownloadFailsWithNoCache(t *testing.T) {
	tmp := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := tranco.NewWithBase(srv.URL, tmp, false)
	ev, err := c.Check(context.Background(), model.IOC{Value: "google.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusError {
		t.Errorf("status = %q, want error", ev.Status)
	}
}

func TestCheckTimeoutClassification(t *testing.T) {
	tmp := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // block until client disconnects
	}))
	defer srv.Close()

	c := tranco.NewWithBase(srv.URL, tmp, false)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	ev, err := c.Check(ctx, model.IOC{Value: "google.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusTimeout {
		t.Errorf("status = %q, want timeout (ctx cancelled during download)", ev.Status)
	}
}

func TestDownloadExtractsZipToCSV(t *testing.T) {
	tmp := t.TempDir()
	csvContent := "1,google.com\n2,youtube.com\n100000,last-top100k.example.com\n500000,deep-in-1m.example.com\n"
	zipData := makeZip(t, csvContent)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/top-1m-id":
			w.Write([]byte("ZIPTEST1"))
		case "/top-1m.csv.zip":
			w.Header().Set("Content-Type", "application/zip")
			w.Write(zipData)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	c := tranco.NewWithBase(srv.URL, tmp, false)

	// google.com rank 1 → top 1M + top 100k bonus.
	ev, err := c.Check(context.Background(), model.IOC{Value: "google.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	assertEvidence(t, ev, model.StatusOk, 2)
	assertHasSignal(t, ev, sources.SignalTrancoTop1M)
	assertHasSignal(t, ev, sources.SignalTrancoTop100k)

	// deep-in-1m.example.com rank 500000 → only top 1M.
	ev, err = c.Check(context.Background(), model.IOC{Value: "deep-in-1m.example.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	assertEvidence(t, ev, model.StatusOk, 1)
	assertHasSignal(t, ev, sources.SignalTrancoTop1M)
	assertNoSignal(t, ev, sources.SignalTrancoTop100k)

	// absent domain → no signals.
	ev, err = c.Check(context.Background(), model.IOC{Value: "evil-phishing.sbs", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	assertEvidence(t, ev, model.StatusOk, 0)

	// Verify the cached file is an extracted CSV, not a ZIP.
	cached, err := os.ReadFile(filepath.Join(tmp, "tranco-1m.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasPrefix(cached, []byte("PK")) {
		t.Fatal("cached file is still a ZIP; extraction failed")
	}
	if !bytes.Contains(cached, []byte("google.com")) {
		t.Error("cached CSV doesn't contain google.com")
	}
}

// Compile-time interface check.
var _ sources.FPSource = (*tranco.Client)(nil)

func assertEvidence(t *testing.T, ev sources.FPEvidence, status model.SourceStatus, signalCount int) {
	t.Helper()
	if ev.Status != status {
		t.Errorf("status = %q, want %q", ev.Status, status)
	}
	if len(ev.Signals) != signalCount {
		t.Errorf("signals = %v (len %d), want len %d", ev.Signals, len(ev.Signals), signalCount)
	}
	if ev.Source != model.SourceTranco {
		t.Errorf("source = %q, want tranco", ev.Source)
	}
}

func assertHasSignal(t *testing.T, ev sources.FPEvidence, sig sources.FPSignal) {
	t.Helper()
	for _, s := range ev.Signals {
		if s == sig {
			return
		}
	}
	t.Errorf("missing signal %q in %v", sig, ev.Signals)
}

func assertNoSignal(t *testing.T, ev sources.FPEvidence, sig sources.FPSignal) {
	t.Helper()
	for _, s := range ev.Signals {
		if s == sig {
			t.Errorf("unexpected signal %q in %v", sig, ev.Signals)
			return
		}
	}
}

func TestMapAndScanEquivalence(t *testing.T) {
	domains := []struct {
		domain     string
		wantStatus model.SourceStatus
		wantCount  int
	}{
		{"google.com", model.StatusOk, 2},
		{"deep-in-1m.example.com", model.StatusOk, 1},
		{"not-in-list.test", model.StatusOk, 0},
		{"cdn.discordapp.com", model.StatusOk, 2},
		{"evil.github.io", model.StatusOk, 0},
	}

	for _, d := range domains {
		mapClient := tranco.NewWithPath(fixturePath, false)
		scanClient := tranco.NewWithPath(fixturePath, true)
		ioc := model.IOC{Value: d.domain, Type: model.TypeDomain}

		mapEv, err := mapClient.Check(context.Background(), ioc)
		if err != nil {
			t.Fatal(err)
		}
		scanEv, err := scanClient.Check(context.Background(), ioc)
		if err != nil {
			t.Fatal(err)
		}

		if mapEv.Status != scanEv.Status {
			t.Errorf("[%s] status mismatch: map=%q scan=%q", d.domain, mapEv.Status, scanEv.Status)
		}
		if len(mapEv.Signals) != len(scanEv.Signals) {
			t.Errorf("[%s] signal count mismatch: map=%d scan=%d", d.domain, len(mapEv.Signals), len(scanEv.Signals))
		}
		for i := range mapEv.Signals {
			if mapEv.Signals[i] != scanEv.Signals[i] {
				t.Errorf("[%s] signal[%d] mismatch: map=%q scan=%q", d.domain, i, mapEv.Signals[i], scanEv.Signals[i])
			}
		}
	}
}

// Silence the fmt import if needed.
var _ = fmt.Sprint
