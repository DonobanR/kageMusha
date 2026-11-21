package urlhaus_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/sources"
	"github.com/DonobanR/kagemusha/internal/sources/urlhaus"
)

func TestAppliesToTypes(t *testing.T) {
	c := urlhaus.New("")
	yes := []model.IOCType{model.TypeDomain, model.TypeIPv4, model.TypeURL, model.TypeHashMD5, model.TypeHashSHA256}
	no := []model.IOCType{model.TypeHashSHA1, model.TypeIPv6}

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

func TestLookupBugOnUnsupportedType(t *testing.T) {
	c := urlhaus.New("")
	_, err := c.Lookup(context.Background(), model.IOC{Value: "::1", Type: model.TypeIPv6})
	if err == nil {
		t.Error("expected error for unsupported type")
	}
}

func TestLookupHostListed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"query_status": "ok",
			"urlhaus_reference": "https://urlhaus.abuse.ch/host/evil.com/",
			"firstseen": "2026-11-15 10:00:00 UTC",
			"url_count": "2",
			"urls": [
				{"threat": "malware_download", "tags": ["emotet", "exe"]},
				{"threat": "malware_download", "tags": ["doc"]}
			]
		}`))
	}))
	defer srv.Close()

	c := urlhaus.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "evil.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %v, want ok", ev.Status)
	}
	if ev.MalwareFamily != "emotet" {
		t.Errorf("family = %q, want emotet", ev.MalwareFamily)
	}
	if ev.Source != model.SourceURLhaus {
		t.Errorf("source = %q, want urlhaus", ev.Source)
	}
	if ev.Reference != "https://urlhaus.abuse.ch/host/evil.com/" {
		t.Errorf("reference = %q", ev.Reference)
	}
	if ev.FirstSeen != "2026-11-15T10:00:00Z" {
		t.Errorf("first_seen = %q, want 2026-11-15T10:00:00Z", ev.FirstSeen)
	}
}

func TestLookupHostNotListed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"query_status": "no_results"}`))
	}))
	defer srv.Close()

	c := urlhaus.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "google.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusNotListed {
		t.Errorf("status = %v, want not_listed", ev.Status)
	}
}

func TestLookupPayloadWithSignature(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"query_status": "ok",
			"signature": "Heodo",
			"file_type": "exe"
		}`))
	}))
	defer srv.Close()

	c := urlhaus.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{
		Value: "d41d8cd98f00b204e9800998ecf8427e",
		Type:  model.TypeHashMD5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %v, want ok", ev.Status)
	}
	if ev.MalwareFamily != "Heodo" {
		t.Errorf("family = %q, want Heodo", ev.MalwareFamily)
	}
}

func TestLookupRateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := urlhaus.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "evil.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusRateLimited {
		t.Errorf("status = %v, want rate_limited", ev.Status)
	}
}

func TestLookupServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := urlhaus.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "evil.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusError {
		t.Errorf("status = %v, want error", ev.Status)
	}
}

func TestLookupTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := urlhaus.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(ctx, model.IOC{Value: "evil.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusTimeout {
		t.Errorf("status = %v, want timeout", ev.Status)
	}
}

func TestLookupMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{not json`))
	}))
	defer srv.Close()

	c := urlhaus.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "evil.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusError {
		t.Errorf("status = %v, want error", ev.Status)
	}
}

func TestAuthKeyHeader(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("Auth-Key")
		w.Write([]byte(`{"query_status": "no_results"}`))
	}))
	defer srv.Close()

	c := urlhaus.NewWithBase(srv.URL, "my-secret-key")
	c.Lookup(context.Background(), model.IOC{Value: "test.com", Type: model.TypeDomain})

	if gotKey != "my-secret-key" {
		t.Errorf("Auth-Key = %q, want my-secret-key", gotKey)
	}
}

func TestLastSeenFromOnlineURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"query_status": "ok",
			"urlhaus_reference": "https://urlhaus.abuse.ch/host/evil.com/",
			"firstseen": "2023-01-13 06:56:03 UTC",
			"url_count": "2",
			"urls": [
				{"threat": "malware_download", "tags": ["mirai"], "url_status": "online", "date_added": "2023-10-02 18:23:05 UTC"},
				{"threat": "malware_download", "tags": ["mirai"], "url_status": "offline", "date_added": "2023-01-13 06:56:25 UTC"}
			]
		}`))
	}))
	defer srv.Close()

	c := urlhaus.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "evil.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.LastSeen == "" {
		t.Fatal("last_seen should not be empty when a URL is online")
	}
	// Online URL → LastSeen is approximately now.
	if ev.FirstSeen == ev.LastSeen {
		t.Error("last_seen should differ from first_seen when a URL is online")
	}
}

func TestLastSeenFromOfflineURLs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"query_status": "ok",
			"urlhaus_reference": "https://urlhaus.abuse.ch/host/194.180.49.139/",
			"firstseen": "2023-01-13 06:56:03 UTC",
			"url_count": "3",
			"urls": [
				{"threat": "malware_download", "tags": ["mirai"], "url_status": "offline", "date_added": "2023-10-02 18:23:05 UTC"},
				{"threat": "malware_download", "tags": ["mirai"], "url_status": "offline", "date_added": "2023-01-30 16:45:32 UTC"},
				{"threat": "malware_download", "tags": ["mirai"], "url_status": "offline", "date_added": "2023-01-13 06:56:25 UTC"}
			]
		}`))
	}))
	defer srv.Close()

	c := urlhaus.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "194.180.49.139", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	// All offline → LastSeen = most recent date_added.
	if ev.LastSeen != "2023-10-02T18:23:05Z" {
		t.Errorf("last_seen = %q, want 2023-10-02T18:23:05Z (most recent date_added)", ev.LastSeen)
	}
}

// Verify interface compliance at compile time.
var _ sources.ThreatSource = (*urlhaus.Client)(nil)

// --- Real-response fixtures (see testdata/README.md) ---

func serveURLhausFixture(t *testing.T, name string, gotPath, gotForm *string) *httptest.Server {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		*gotPath = r.URL.Path
		*gotForm = r.Form.Encode()
		w.Write(data)
	}))
}

func TestFixtureURLEndpoint(t *testing.T) {
	var path, form string
	srv := serveURLhausFixture(t, "url_123_130_64_237_59149_i.json", &path, &form)
	defer srv.Close()

	now := time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC)
	c := urlhaus.NewWithBaseClock(srv.URL, "test-key", func() time.Time { return now })
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "http://123.130.64.237:59149/i", Type: model.TypeURL})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/url/" || form != "url=http%3A%2F%2F123.130.64.237%3A59149%2Fi" {
		t.Errorf("request = %s %s, want /url/ with url= param", path, form)
	}
	if ev.Status != model.StatusOk {
		t.Fatalf("status = %q, want ok", ev.Status)
	}
	if ev.Reference != "https://urlhaus.abuse.ch/url/4072111/" {
		t.Errorf("reference = %q", ev.Reference)
	}
	if ev.FirstSeen != "2026-11-21T00:41:13Z" {
		t.Errorf("first_seen = %q, want date_added normalized", ev.FirstSeen)
	}
	if ev.LastSeen != "2026-11-21T06:00:00Z" {
		t.Errorf("last_seen = %q, want now (url_status online)", ev.LastSeen)
	}
	// Real tags ["32-bit","elf","mips","Mozi"]: architecture/format tags are skipped.
	if ev.MalwareFamily != "Mozi" {
		t.Errorf("family = %q, want Mozi", ev.MalwareFamily)
	}
}

// Real capture: offline URL from 2023. last_online carries a masked time of
// day ("2023-10-03 20:XX:XX UTC"), which must still yield a date.
func TestFixtureURLOfflineLastOnline(t *testing.T) {
	var path, form string
	srv := serveURLhausFixture(t, "url_194_180_49_139_offline.json", &path, &form)
	defer srv.Close()

	now := time.Date(2026, 11, 21, 6, 0, 0, 0, time.UTC)
	c := urlhaus.NewWithBaseClock(srv.URL, "test-key", func() time.Time { return now })
	ev, err := c.Lookup(context.Background(), model.IOC{
		Value: "http://194.180.49.139/f2q2kke5aadloo4aasdjjjfirbmw/0xh0roxxnavebusyoo.arm7", Type: model.TypeURL})
	if err != nil {
		t.Fatal(err)
	}
	if ev.LastSeen != "2023-10-03T00:00:00Z" {
		t.Errorf("last_seen = %q, want 2023-10-03T00:00:00Z (masked time of day → date only)", ev.LastSeen)
	}
	if ev.FirstSeen != "2023-10-02T18:23:05Z" {
		t.Errorf("first_seen = %q", ev.FirstSeen)
	}
	if ev.MalwareFamily != "mirai" {
		t.Errorf("family = %q, want mirai (tags [elf, mirai])", ev.MalwareFamily)
	}
}

func TestFamilySkipsArchitectureAndFormatTags(t *testing.T) {
	cases := []struct {
		tags []string
		want string
	}{
		{[]string{"32-bit", "elf", "mips", "Mozi"}, "Mozi"},
		{[]string{"ELF", "Arm7", "mirai"}, "mirai"},
		{[]string{"exe", "x86-64", "Emotet"}, "Emotet"},
		{[]string{"32-bit", "elf"}, ""},
		{nil, ""},
	}
	for _, tc := range cases {
		body := `{"query_status":"ok","urls":[{"tags":[`
		for i, tg := range tc.tags {
			if i > 0 {
				body += ","
			}
			body += `"` + tg + `"`
		}
		body += `]}]}`
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		c := urlhaus.NewWithBase(srv.URL, "k")
		ev, err := c.Lookup(context.Background(), model.IOC{Value: "1.2.3.4", Type: model.TypeIPv4})
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		if ev.MalwareFamily != tc.want {
			t.Errorf("tags %v → family %q, want %q", tc.tags, ev.MalwareFamily, tc.want)
		}
	}
}

func TestFixturePayloadEndpoint(t *testing.T) {
	var path, form string
	srv := serveURLhausFixture(t, "payload_md5_59ce0bab.json", &path, &form)
	defer srv.Close()

	c := urlhaus.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "59ce0baba11893f90527fc951ac69912", Type: model.TypeHashMD5})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/payload/" || form != "md5_hash=59ce0baba11893f90527fc951ac69912" {
		t.Errorf("request = %s %s, want /payload/ with md5_hash= param", path, form)
	}
	if ev.Status != model.StatusOk {
		t.Fatalf("status = %q, want ok", ev.Status)
	}
	if ev.MalwareFamily != "" {
		t.Errorf("family = %q, want empty (signature is null in the real response)", ev.MalwareFamily)
	}
	if ev.FirstSeen != "2020-09-27T22:50:05Z" {
		t.Errorf("first_seen = %q, want top-level firstseen normalized", ev.FirstSeen)
	}
}
