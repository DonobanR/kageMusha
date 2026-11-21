package otx_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/sources"
	"github.com/DonobanR/kagemusha/internal/sources/otx"
)

func TestAppliesToAllExpectedTypes(t *testing.T) {
	c := otx.New("")
	for _, typ := range []model.IOCType{
		model.TypeIPv4, model.TypeIPv6, model.TypeDomain, model.TypeURL,
		model.TypeHashMD5, model.TypeHashSHA1, model.TypeHashSHA256,
	} {
		if !c.AppliesTo(typ) {
			t.Errorf("expected AppliesTo(%s) = true", typ)
		}
	}
}

func TestBugOnUnsupportedType(t *testing.T) {
	c := otx.New("")
	_, err := c.Lookup(context.Background(), model.IOC{Value: "test", Type: "unknown"})
	if err == nil {
		t.Error("expected BUG error for unsupported type")
	}
}

func TestLookupFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/IPv4/") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("X-OTX-API-KEY") != "test-key" {
			t.Error("missing API key header")
		}
		fmt.Fprint(w, `{
			"pulse_info": {
				"count": 3,
				"pulses": [
					{
						"id": "abc123def456",
						"name": "Cobalt Strike C2 Infrastructure",
						"tags": ["malware", "cobalt-strike", "c2"],
						"created": "2026-11-10T08:30:00.000000",
						"malware_families": ["Cobalt Strike"]
					}
				]
			}
		}`)
	}))
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "1.2.3.4", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %q, want ok", ev.Status)
	}
	if ev.MalwareFamily != "Cobalt Strike" {
		t.Errorf("family = %q, want Cobalt Strike", ev.MalwareFamily)
	}
	if ev.Source != model.SourceOTX {
		t.Errorf("source = %q, want otx", ev.Source)
	}
	if ev.Reference != "https://otx.alienvault.com/pulse/abc123def456" {
		t.Errorf("reference = %q", ev.Reference)
	}
	if ev.FirstSeen != "2026-11-10T08:30:00Z" {
		t.Errorf("first_seen = %q, want 2026-11-10T08:30:00Z", ev.FirstSeen)
	}
}

func TestLookupNotListed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"pulse_info": {"count": 0, "pulses": []}}`)
	}))
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "google.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusNotListed {
		t.Errorf("status = %q, want not_listed", ev.Status)
	}
}

func TestLookupDomain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/domain/evil.com/general") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		fmt.Fprint(w, `{
			"pulse_info": {
				"count": 1,
				"pulses": [{"name": "Phishing Campaign", "tags": ["phishing"], "malware_families": []}]
			}
		}`)
	}))
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "evil.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %q", ev.Status)
	}
	if ev.MalwareFamily != "" {
		t.Errorf("family = %q, want empty (no malware_families)", ev.MalwareFamily)
	}
}

func TestLookupHash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/file/abc123/general") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		fmt.Fprint(w, `{
			"pulse_info": {
				"count": 2,
				"pulses": [{"name": "Ransomware Hashes", "tags": ["ransomware", "lockbit"], "malware_families": ["LockBit"]}]
			}
		}`)
	}))
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "abc123", Type: model.TypeHashSHA256})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %q", ev.Status)
	}
	if ev.MalwareFamily != "LockBit" {
		t.Errorf("family = %q, want LockBit", ev.MalwareFamily)
	}
}

func TestRateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "1.2.3.4", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusRateLimited {
		t.Errorf("status = %q, want rate_limited", ev.Status)
	}
}

func TestServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "1.2.3.4", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusError {
		t.Errorf("status = %q, want error", ev.Status)
	}
}

func TestForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "1.2.3.4", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusError {
		t.Errorf("status = %q, want error", ev.Status)
	}
}

func TestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	ev, err := c.Lookup(ctx, model.IOC{Value: "1.2.3.4", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusTimeout {
		t.Errorf("status = %q, want timeout", ev.Status)
	}
}

func TestRetryAfter429(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, `{
			"pulse_info": {
				"count": 1,
				"pulses": [{"id": "retry1", "name": "After Retry", "tags": ["test"], "created": "2026-11-01T00:00:00.000000"}]
			}
		}`)
	}))
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "1.2.3.4", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %q after retry, want ok", ev.Status)
	}
	if calls != 2 {
		t.Errorf("expected 2 calls (initial + retry), got %d", calls)
	}
}

func TestRetryStillRateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "1.2.3.4", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusRateLimited {
		t.Errorf("status = %q, want rate_limited (both attempts 429)", ev.Status)
	}
}

func TestMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{invalid json`)
	}))
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "1.2.3.4", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusError {
		t.Errorf("status = %q, want error", ev.Status)
	}
}

func TestNoFamilyWithoutMalwareFamilies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{
			"pulse_info": {
				"count": 1,
				"pulses": [{"name": "APT28 Infrastructure", "tags": ["apt", "malware"], "malware_families": []}]
			}
		}`)
	}))
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "1.2.3.4", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.MalwareFamily != "" {
		t.Errorf("family = %q, want empty (no malware_families, should not fall back to pulse name)", ev.MalwareFamily)
	}
}

func TestMostRecentPulseForReference(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{
			"pulse_info": {
				"count": 3,
				"pulses": [
					{"id": "old1", "name": "Old Feed", "created": "2022-10-11T13:14:18.000000", "modified": "2026-11-21T00:08:59.000000", "malware_families": []},
					{"id": "newest", "name": "Botnet C2 Nov 2026", "created": "2026-11-20T20:43:43.000000", "malware_families": ["Emotet"]},
					{"id": "mid1", "name": "Mid Feed", "created": "2025-06-01T00:00:00.000000", "malware_families": []}
				]
			}
		}`)
	}))
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "1.2.3.4", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Reference != "https://otx.alienvault.com/pulse/newest" {
		t.Errorf("reference = %q, want pulse 'newest' (most recently created)", ev.Reference)
	}
	if ev.FirstSeen != "2022-10-11T13:14:18Z" {
		t.Errorf("first_seen = %q, want oldest pulse date", ev.FirstSeen)
	}
	if ev.LastSeen != "2026-11-20T20:43:43Z" {
		t.Errorf("last_seen = %q, want most recent created date", ev.LastSeen)
	}
	if ev.MalwareFamily != "Emotet" {
		t.Errorf("family = %q, want Emotet (from malware_families)", ev.MalwareFamily)
	}
}

func TestWhitelistedDomainNotListed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{
			"validation": [
				{"source": "akamai", "name": "Akamai Popular Domain"},
				{"source": "whitelist", "name": "Whitelisted domain"}
			],
			"pulse_info": {
				"count": 50,
				"pulses": [
					{"id": "abc123", "name": "Sauron Feed", "tags": [], "created": "2022-05-25T10:04:39.000000"}
				]
			}
		}`)
	}))
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "amazon.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusSuppressed {
		t.Errorf("status = %q, want suppressed (whitelisted domain should be suppressed despite pulses)", ev.Status)
	}
	if ev.Extra == "" {
		t.Error("Extra should contain suppression detail")
	}
}

func TestNonWhitelistedDomainStillVotes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{
			"validation": [],
			"pulse_info": {
				"count": 2,
				"pulses": [{"id": "xyz", "name": "Phishing Feed", "tags": ["phishing"], "created": "2026-11-01T00:00:00.000000"}]
			}
		}`)
	}))
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "evil.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %q, want ok (non-whitelisted with pulses should vote)", ev.Status)
	}
}

func TestCloudProviderNotSuppressed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{
			"validation": [
				{"source": "cloud", "name": "Cloud Provider IP range"}
			],
			"pulse_info": {
				"count": 50,
				"pulses": [{"id": "abc", "name": "C2 Infrastructure", "tags": ["c2", "cobalt-strike"], "created": "2026-10-01T00:00:00.000000", "malware_families": ["Cobalt Strike"]}]
			}
		}`)
	}))
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "10.20.30.40", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %q, want ok (cloud provider is multi-tenant, must not suppress C2 pulses)", ev.Status)
	}
}

func TestCloudPlusWhitelistZeroPulses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{
			"validation": [
				{"source": "cloud", "name": "Cloud Provider IP range"},
				{"source": "whitelist", "name": "Whitelisted IP"}
			],
			"pulse_info": {
				"count": 0,
				"pulses": []
			}
		}`)
	}))
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "8.8.8.8", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusNotListed {
		t.Errorf("status = %q, want not_listed (0 pulses means no data, regardless of validation)", ev.Status)
	}
}

func TestAdNetworkNotSuppressed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{
			"validation": [
				{"source": "ad_network", "name": "Whitelisted ad network domain"}
			],
			"pulse_info": {
				"count": 5,
				"pulses": [{"id": "xyz", "name": "Noise Feed", "tags": [], "created": "2024-01-01T00:00:00.000000"}]
			}
		}`)
	}))
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "doubleclick.net", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %q, want ok (ad_network is a malvertising vector, must not suppress)", ev.Status)
	}
}

func serveFixture(t *testing.T, name string) *httptest.Server {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
}

func TestFixtureAmazonComWhitelisted(t *testing.T) {
	srv := serveFixture(t, "domain_amazon_com_whitelisted.json")
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "amazon.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusSuppressed {
		t.Errorf("status = %q, want suppressed", ev.Status)
	}
	if ev.Extra == "" {
		t.Error("Extra should contain suppression detail")
	}
}

func TestFixtureGoogleComZeroPulses(t *testing.T) {
	srv := serveFixture(t, "domain_google_com_whitelisted.json")
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "google.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusNotListed {
		t.Errorf("status = %q, want not_listed (0 pulses means no data)", ev.Status)
	}
}

func TestFixture8888ZeroPulses(t *testing.T) {
	srv := serveFixture(t, "ipv4_8_8_8_8_whitelisted.json")
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "8.8.8.8", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusNotListed {
		t.Errorf("status = %q, want not_listed (0 pulses means no data)", ev.Status)
	}
}

func TestFixtureCloudProviderNotSuppressed(t *testing.T) {
	srv := serveFixture(t, "ipv4_13_107_42_14_cloud.json")
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "13.107.42.14", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %q, want ok (cloud-only validation must not suppress)", ev.Status)
	}
}

func TestFixtureMalwareFamiliesAsObjects(t *testing.T) {
	srv := serveFixture(t, "ipv4_194_180_49_139.json")
	defer srv.Close()

	c := otx.NewWithBase(srv.URL, "")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "194.180.49.139", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %q, want ok (object-form malware_families must not break parsing)", ev.Status)
	}
	// Fixture has 3 Mirai variants each in 1 pulse: no clear winner.
	if ev.MalwareFamily != "" {
		t.Errorf("family = %q, want empty (3 variants at count 1 each = no clear winner)", ev.MalwareFamily)
	}
	if ev.Extra != "9 pulse(s)" {
		t.Errorf("extra = %q, want '9 pulse(s)' (pulse count fallback when no family)", ev.Extra)
	}
}

// Compile-time interface check.
var _ sources.ThreatSource = (*otx.Client)(nil)
