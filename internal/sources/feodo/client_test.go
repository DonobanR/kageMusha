package feodo_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/sources"
	"github.com/DonobanR/kagemusha/internal/sources/feodo"
)

func TestAppliesTo(t *testing.T) {
	c := feodo.NewWithPath("testdata/fixture.csv")
	yes := []model.IOCType{model.TypeIPv4}
	no := []model.IOCType{model.TypeIPv6, model.TypeDomain, model.TypeURL, model.TypeHashMD5, model.TypeHashSHA1, model.TypeHashSHA256}

	for _, typ := range yes {
		if !c.AppliesTo(typ) {
			t.Errorf("expected AppliesTo(%s) = true", typ)
		}
	}
	for _, typ := range no {
		if c.AppliesTo(typ) {
			t.Errorf("expected AppliesTo(%s) = false", typ)
		}
	}
}

func TestLookupIPListed(t *testing.T) {
	c := feodo.NewWithPath("testdata/fixture.csv")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "192.168.1.1", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %v, want ok", ev.Status)
	}
	if ev.MalwareFamily != "Emotet" {
		t.Errorf("family = %q, want Emotet", ev.MalwareFamily)
	}
	if ev.Source != model.SourceFeodo {
		t.Errorf("source = %q, want feodo", ev.Source)
	}
	if ev.Reference != "https://feodotracker.abuse.ch/browse/host/192.168.1.1/" {
		t.Errorf("reference = %q", ev.Reference)
	}
	if ev.FirstSeen == "" {
		t.Error("first_seen should not be empty")
	}
}

func TestLastSeenDateOnlyFormat(t *testing.T) {
	c := feodo.NewWithPath("testdata/fixture.csv")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "192.168.1.1", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.LastSeen != "2024-01-02T00:00:00Z" {
		t.Errorf("last_seen = %q, want 2024-01-02T00:00:00Z (date-only format)", ev.LastSeen)
	}
}

func TestLookupIPNotListed(t *testing.T) {
	c := feodo.NewWithPath("testdata/fixture.csv")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "8.8.8.8", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusNotListed {
		t.Errorf("status = %v, want not_listed", ev.Status)
	}
}

func TestLookupBugOnUnsupportedType(t *testing.T) {
	c := feodo.NewWithPath("testdata/fixture.csv")
	_, err := c.Lookup(context.Background(), model.IOC{Value: "evil.com", Type: model.TypeDomain})
	if err == nil {
		t.Error("expected error for unsupported type")
	}
}

func TestCacheTTL(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Write([]byte("# test\n\"first_seen_utc\",\"dst_ip\",\"dst_port\",\"c2_status\",\"last_online\",\"malware\"\n\"2024-01-01\",\"1.2.3.4\",\"443\",\"online\",\"2024-01-02\",\"TestBot\"\n"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	c := feodo.NewWithBase(srv.URL, dir)

	// First lookup downloads.
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "1.2.3.4", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("first lookup: status = %v, want ok", ev.Status)
	}
	if requests.Load() != 1 {
		t.Errorf("expected 1 download, got %d", requests.Load())
	}

	// Second client with same cache dir — no new download (cache is fresh).
	c2 := feodo.NewWithBase(srv.URL, dir)
	ev2, err := c2.Lookup(context.Background(), model.IOC{Value: "1.2.3.4", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev2.Status != model.StatusOk {
		t.Errorf("cached lookup: status = %v, want ok", ev2.Status)
	}
	if requests.Load() != 1 {
		t.Errorf("expected still 1 download (cached), got %d", requests.Load())
	}
}

func TestDownloadFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	c := feodo.NewWithBase(srv.URL, dir)

	ev, err := c.Lookup(context.Background(), model.IOC{Value: "1.2.3.4", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusError {
		t.Errorf("status = %v, want error", ev.Status)
	}
}

func TestStaleCache(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "feodo-ipblocklist.csv")
	os.WriteFile(cachePath, []byte("# stale\n\"first_seen_utc\",\"dst_ip\",\"dst_port\",\"c2_status\",\"last_online\",\"malware\"\n\"2024-01-01\",\"5.6.7.8\",\"443\",\"online\",\"2024-01-02\",\"Stale\"\n"), 0o644)

	// Make cache old by backdating mod time.
	past := time.Now().Add(-48 * time.Hour)
	os.Chtimes(cachePath, past, past)

	// Server is down — should fall back to stale cache.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := feodo.NewWithBase(srv.URL, dir)
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "5.6.7.8", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %v, want ok (stale cache fallback)", ev.Status)
	}
	if ev.MalwareFamily != "Stale" {
		t.Errorf("family = %q, want Stale", ev.MalwareFamily)
	}
}

func TestStaleCSVWarning(t *testing.T) {
	c := feodo.NewWithPath("testdata/fixture.csv")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "192.168.1.1", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Fatalf("status = %v, want ok", ev.Status)
	}
	// Fixture has "# Last updated: 2024-01-01 00:00:00 UTC" which is >7 days old
	if !strings.Contains(ev.Extra, "CSV is") || !strings.Contains(ev.Extra, "days old") {
		t.Errorf("Extra = %q, want staleness warning (CSV is N days old)", ev.Extra)
	}
}

// Compile-time interface check.
var _ sources.ThreatSource = (*feodo.Client)(nil)
