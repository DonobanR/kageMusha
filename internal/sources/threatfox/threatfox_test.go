package threatfox_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/sources"
	"github.com/DonobanR/kagemusha/internal/sources/threatfox"
)

func TestAppliesToTypes(t *testing.T) {
	c := threatfox.New("")
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
	c := threatfox.New("")
	_, err := c.Lookup(context.Background(), model.IOC{Value: "::1", Type: model.TypeIPv6})
	if err == nil {
		t.Error("expected error for unsupported type")
	}
}

func TestLookupDomainListed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		if req["query"] != "search_ioc" {
			t.Errorf("query = %v, want search_ioc", req["query"])
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"query_status": "ok",
			"data": [
				{
					"id": "987654",
					"ioc": "evil.com",
					"malware_printable": "Emotet",
					"threat_type": "botnet_cc",
					"confidence_level": 75,
					"first_seen": "2026-11-18 14:30:00 UTC"
				}
			]
		}`))
	}))
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "evil.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %v, want ok", ev.Status)
	}
	if ev.MalwareFamily != "Emotet" {
		t.Errorf("family = %q, want Emotet", ev.MalwareFamily)
	}
	if ev.Source != model.SourceThreatFox {
		t.Errorf("source = %q, want threatfox", ev.Source)
	}
	if ev.Reference != "https://threatfox.abuse.ch/ioc/987654" {
		t.Errorf("reference = %q", ev.Reference)
	}
	if ev.FirstSeen != "2026-11-18T14:30:00Z" {
		t.Errorf("first_seen = %q, want 2026-11-18T14:30:00Z", ev.FirstSeen)
	}
}

func TestLookupDomainNotListed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"query_status": "no_result", "data": null}`))
	}))
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "google.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusNotListed {
		t.Errorf("status = %v, want not_listed", ev.Status)
	}
}

func TestLookupHashUsesSearchIOC(t *testing.T) {
	var gotQuery, gotSearchTerm string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		json.NewDecoder(r.Body).Decode(&req)
		gotQuery, _ = req["query"].(string)
		gotSearchTerm, _ = req["search_term"].(string)
		w.Write([]byte(`{
			"query_status": "ok",
			"data": [
				{
					"id": "2037200",
					"ioc": "d41d8cd98f00b204e9800998ecf8427e",
					"ioc_type": "md5_hash",
					"malware_printable": "AgentTesla",
					"threat_type": "payload",
					"confidence_level": 90,
					"reporter": "anonymous",
					"first_seen": "2026-11-20 10:00:00 UTC"
				}
			]
		}`))
	}))
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{
		Value: "d41d8cd98f00b204e9800998ecf8427e",
		Type:  model.TypeHashMD5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery != "search_ioc" {
		t.Errorf("query = %q, want search_ioc", gotQuery)
	}
	if gotSearchTerm != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("search_term = %q, want the hash value", gotSearchTerm)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %v, want ok", ev.Status)
	}
	if ev.MalwareFamily != "AgentTesla" {
		t.Errorf("family = %q, want AgentTesla", ev.MalwareFamily)
	}
}

func TestLookupRateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "test-key")
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

	c := threatfox.NewWithBase(srv.URL, "test-key")
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

	c := threatfox.NewWithBase(srv.URL, "test-key")
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

	c := threatfox.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "evil.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusError {
		t.Errorf("status = %v, want error", ev.Status)
	}
}

func TestLookupEmptyDataArray(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"query_status": "ok", "data": []}`))
	}))
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "clean.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusNotListed {
		t.Errorf("status = %v, want not_listed", ev.Status)
	}
}

func TestLookupDataFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"query_status": "ok", "data": false}`))
	}))
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "clean.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusNotListed {
		t.Errorf("status = %v, want not_listed (data:false edge case)", ev.Status)
	}
}

func TestLookupIllegalSearchTerm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"query_status": "illegal_search_term", "data": null}`))
	}))
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "???", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusError {
		t.Errorf("status = %v, want error (illegal_search_term is operational error, not not_listed)", ev.Status)
	}
}

func TestAuthKeyHeader(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("Auth-Key")
		w.Write([]byte(`{"query_status": "no_result", "data": null}`))
	}))
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "my-secret-key")
	c.Lookup(context.Background(), model.IOC{Value: "test.com", Type: model.TypeDomain})

	if gotKey != "my-secret-key" {
		t.Errorf("Auth-Key = %q, want my-secret-key", gotKey)
	}
}

func TestLookupRejectsSubstringMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"query_status": "ok",
			"data": [
				{
					"id": "111",
					"ioc": "http://evil.tld/google.com/shell.php",
					"malware_printable": "php.shin_webshell",
					"threat_type": "payload",
					"confidence_level": 50
				},
				{
					"id": "222",
					"ioc": "google.com.evil.tld",
					"malware_printable": "Phishing",
					"threat_type": "payload",
					"confidence_level": 60
				}
			]
		}`))
	}))
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "google.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusNotListed {
		t.Errorf("status = %v, want not_listed (substring matches should be rejected)", ev.Status)
	}
}

func TestLookupAcceptsExactMatchAmongSubstrings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"query_status": "ok",
			"data": [
				{
					"id": "111",
					"ioc": "http://evil.tld/evil.com/shell.php",
					"malware_printable": "Webshell",
					"threat_type": "payload",
					"confidence_level": 50
				},
				{
					"id": "222",
					"ioc": "evil.com",
					"malware_printable": "Emotet",
					"threat_type": "botnet_cc",
					"confidence_level": 75
				}
			]
		}`))
	}))
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "evil.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %v, want ok (exact match exists among results)", ev.Status)
	}
	if ev.MalwareFamily != "Emotet" {
		t.Errorf("family = %q, want Emotet (from exact match, not substring)", ev.MalwareFamily)
	}
}

func TestLookupMatchesIPPort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"query_status": "ok",
			"data": [
				{
					"id": "333",
					"ioc": "162.243.103.246:8080",
					"ioc_type": "ip:port",
					"malware_printable": "Cobalt Strike",
					"threat_type": "botnet_cc",
					"confidence_level": 90
				}
			]
		}`))
	}))
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "162.243.103.246", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %v, want ok (ip:port should match IP query)", ev.Status)
	}
	if ev.MalwareFamily != "Cobalt Strike" {
		t.Errorf("family = %q, want Cobalt Strike", ev.MalwareFamily)
	}
}

func TestLookupMatchesDomainInURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"query_status": "ok",
			"data": [
				{
					"id": "444",
					"ioc": "http://evil.com/payload.exe",
					"ioc_type": "url",
					"malware_printable": "Emotet",
					"threat_type": "payload_delivery",
					"confidence_level": 80
				}
			]
		}`))
	}))
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "evil.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %v, want ok (URL host matches domain query)", ev.Status)
	}
	if ev.MalwareFamily != "Emotet" {
		t.Errorf("family = %q, want Emotet", ev.MalwareFamily)
	}
}

func TestLookupRejectsDomainInURLPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"query_status": "ok",
			"data": [
				{
					"id": "555",
					"ioc": "http://attacker.tld/google.com/phish.html",
					"ioc_type": "url",
					"malware_printable": "Phishing",
					"threat_type": "payload_delivery",
					"confidence_level": 60
				}
			]
		}`))
	}))
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "google.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusNotListed {
		t.Errorf("status = %v, want not_listed (domain in URL path is not a match)", ev.Status)
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

func TestFixtureIPPortMatch(t *testing.T) {
	srv := serveFixture(t, "search_ioc_162_243_103_246.json")
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "162.243.103.246", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Errorf("status = %q, want ok (ip:port entries must match bare IP)", ev.Status)
	}
	if ev.MalwareFamily == "" {
		t.Error("expected a malware family")
	}
}

func TestFixtureSubstringReject(t *testing.T) {
	srv := serveFixture(t, "search_ioc_google_com.json")
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "google.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusNotListed {
		t.Errorf("status = %q, want not_listed (no entry has google.com as exact host)", ev.Status)
	}
}

func TestFixtureOldAnchorNotPreferred(t *testing.T) {
	srv := serveFixture(t, "search_ioc_162_243_103_246.json")
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "162.243.103.246", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	// Both entries are old (>30 days). The anchor-grade Emotet entry
	// (abuse_ch, 2022-07-04) does NOT get preference because it is stale.
	// The most recent entry (Cobalt Strike, 2024-06-14) wins instead.
	if ev.MalwareFamily != "Cobalt Strike" {
		t.Errorf("family = %q, want Cobalt Strike (most recent entry wins when anchor is stale)", ev.MalwareFamily)
	}
	if ev.Anchor {
		t.Error("Anchor = true, want false (anchor entry is stale, so Anchor not set)")
	}
}

func TestFreshAnchorPreferred(t *testing.T) {
	// When the anchor-grade entry is recent (<30 days), it wins over
	// a more recent non-anchor entry.
	now := time.Now().UTC()
	fresh := now.Add(-7 * 24 * time.Hour).Format("2006-01-02 15:04:05 UTC")
	older := now.Add(-3 * 24 * time.Hour).Format("2006-01-02 15:04:05 UTC")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fmt.Sprintf(`{
			"query_status": "ok",
			"data": [
				{
					"id": "100",
					"ioc": "1.2.3.4:443",
					"malware_printable": "Cobalt Strike",
					"threat_type": "botnet_cc",
					"reporter": "anonymous",
					"first_seen": "%s"
				},
				{
					"id": "200",
					"ioc": "1.2.3.4:8080",
					"malware_printable": "Emotet",
					"threat_type": "botnet_cc",
					"reporter": "abuse_ch",
					"first_seen": "%s"
				}
			]
		}`, older, fresh)))
	}))
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "1.2.3.4", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.MalwareFamily != "Emotet" {
		t.Errorf("family = %q, want Emotet (fresh anchor-grade entry preferred)", ev.MalwareFamily)
	}
	if !ev.Anchor {
		t.Error("Anchor = false, want true (fresh abuse_ch + botnet_cc)")
	}
}

func TestNonAnchorGradeEntry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"query_status": "ok",
			"data": [{
				"id": "999",
				"ioc": "evil.com",
				"malware_printable": "Cobalt Strike",
				"threat_type": "botnet_cc",
				"confidence_level": 90,
				"reporter": "anonymous",
				"first_seen": "2026-11-01 00:00:00 UTC"
			}]
		}`))
	}))
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "evil.com", Type: model.TypeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Anchor {
		t.Error("Anchor = true, want false (reporter is anonymous, not abuse_ch)")
	}
}

func TestMultipleFamiliesInExtra(t *testing.T) {
	now := time.Now().UTC()
	fresh := now.Add(-5 * 24 * time.Hour).Format("2006-01-02 15:04:05 UTC")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fmt.Sprintf(`{
			"query_status": "ok",
			"data": [
				{"id":"1","ioc":"1.2.3.4:443","malware_printable":"Cobalt Strike","threat_type":"botnet_cc","reporter":"abuse_ch","first_seen":"%s"},
				{"id":"2","ioc":"1.2.3.4:8080","malware_printable":"Emotet","threat_type":"botnet_cc","reporter":"anonymous","first_seen":"%s"},
				{"id":"3","ioc":"1.2.3.4:9090","malware_printable":"QakBot","threat_type":"botnet_cc","reporter":"anonymous","first_seen":"%s"},
				{"id":"4","ioc":"1.2.3.4:4444","malware_printable":"Cobalt Strike","threat_type":"payload_delivery","reporter":"anonymous","first_seen":"%s"}
			]
		}`, fresh, fresh, fresh, fresh)))
	}))
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "1.2.3.4", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.MalwareFamily != "Cobalt Strike" {
		t.Errorf("family = %q, want Cobalt Strike (fresh anchor)", ev.MalwareFamily)
	}
	if ev.Extra != "also: Emotet, QakBot" {
		t.Errorf("extra = %q, want 'also: Emotet, QakBot' (deduplicated additional families)", ev.Extra)
	}
}

// Real capture (2026-11-21) for 13.233.232.1: two "anonymous" entries (most
// recent by first_seen) and one reporter=abuse_ch entry (id 2034929). The
// anchor comes from the abuse_ch entry only; "anonymous" is a distinct
// reporter value and never qualifies.
func TestFixtureAnchorFromAbuseCHEntry(t *testing.T) {
	srv := serveFixture(t, "search_ioc_13_233_232_1.json")
	defer srv.Close()

	clock := func() time.Time { return time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC) }
	c := threatfox.NewWithBaseClock(srv.URL, "test-key", clock)
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "13.233.232.1", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if !ev.Anchor {
		t.Error("Anchor = false, want true (entry 2034929 is abuse_ch + botnet_cc, last_seen fresh)")
	}
	if ev.Reference != "https://threatfox.abuse.ch/ioc/2034929" {
		t.Errorf("reference = %q, want entry 2034929 (the abuse_ch one, not an anonymous one)", ev.Reference)
	}
}

func TestFixtureAnonymousOnlyIsNotAnchor(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "search_ioc_13_233_232_1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		QueryStatus string           `json:"query_status"`
		Data        []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var kept []map[string]any
	for _, e := range doc.Data {
		if e["reporter"] == "anonymous" {
			kept = append(kept, e)
		}
	}
	if len(kept) != 2 {
		t.Fatalf("fixture changed: expected 2 anonymous entries, got %d", len(kept))
	}
	doc.Data = kept
	filtered, _ := json.Marshal(doc)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(filtered)
	}))
	defer srv.Close()

	clock := func() time.Time { return time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC) }
	c := threatfox.NewWithBaseClock(srv.URL, "test-key", clock)
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "13.233.232.1", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Status != model.StatusOk {
		t.Fatalf("status = %q, want ok", ev.Status)
	}
	if ev.Anchor {
		t.Error("Anchor = true, want false (reporter=anonymous entries only)")
	}
}

// Real capture: search_ioc with a hash term returns the sample entry itself
// (ioc_type md5_hash, threat_type payload, reporter "Grim"). Not anchor-grade.
func TestFixtureHashSearchIOC(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "search_ioc_hash_md5_e39950f0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Write(data)
	}))
	defer srv.Close()

	c := threatfox.NewWithBase(srv.URL, "test-key")
	ev, err := c.Lookup(context.Background(), model.IOC{Value: "e39950f0b39918d0fb7e880932f73812", Type: model.TypeHashMD5})
	if err != nil {
		t.Fatal(err)
	}
	if gotBody != `{"query":"search_ioc","search_term":"e39950f0b39918d0fb7e880932f73812"}` {
		t.Errorf("request body = %s", gotBody)
	}
	if ev.Status != model.StatusOk {
		t.Fatalf("status = %q, want ok", ev.Status)
	}
	if ev.MalwareFamily != "ZStealer" {
		t.Errorf("family = %q, want ZStealer", ev.MalwareFamily)
	}
	if ev.Anchor {
		t.Error("Anchor = true, want false (threat_type payload, reporter Grim)")
	}
	if ev.Reference != "https://threatfox.abuse.ch/ioc/2037211" {
		t.Errorf("reference = %q", ev.Reference)
	}
	if ev.FirstSeen != "2026-11-21T02:45:36Z" {
		t.Errorf("first_seen = %q", ev.FirstSeen)
	}
}

// Verify interface compliance at compile time.
var _ sources.ThreatSource = (*threatfox.Client)(nil)
