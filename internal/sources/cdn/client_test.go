package cdn_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/sources"
	"github.com/DonobanR/kagemusha/internal/sources/cdn"
)

func TestAppliesTo(t *testing.T) {
	c := cdn.NewWithCIDRs("Test", []string{"1.0.0.0/24"})
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

func TestEnrichIPInCloudflareRange(t *testing.T) {
	c := cdn.NewWithCIDRs("Cloudflare", []string{"104.16.0.0/13", "172.64.0.0/13"})
	ctx, err := c.Enrich(context.Background(), model.IOC{Value: "104.16.5.1", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if len(ctx) != 1 {
		t.Fatalf("context = %v, want 1 entry", ctx)
	}
	if ctx[0] != "Hosted in Cloudflare (Cloud Infrastructure)" {
		t.Errorf("context = %q, want Cloudflare", ctx[0])
	}
}

func TestEnrichIPNotInRange(t *testing.T) {
	c := cdn.NewWithCIDRs("Cloudflare", []string{"104.16.0.0/13"})
	ctx, err := c.Enrich(context.Background(), model.IOC{Value: "8.8.8.8", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if len(ctx) != 0 {
		t.Errorf("context = %v, want empty (IP not in cloud range)", ctx)
	}
}

func TestEnrichBugOnUnsupportedType(t *testing.T) {
	c := cdn.NewWithCIDRs("Test", []string{"1.0.0.0/24"})
	_, err := c.Enrich(context.Background(), model.IOC{Value: "evil.com", Type: model.TypeDomain})
	if err == nil {
		t.Error("expected error for unsupported type")
	}
}

func TestEnrichReturnsProviderName(t *testing.T) {
	c := cdn.NewWithCIDRs("AWS", []string{"3.0.0.0/15"})
	ctx, err := c.Enrich(context.Background(), model.IOC{Value: "3.0.1.1", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if len(ctx) != 1 || ctx[0] != "Hosted in AWS (Cloud Infrastructure)" {
		t.Errorf("context = %v, want AWS", ctx)
	}
}

func TestDownloadAndCache(t *testing.T) {
	cfSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("104.16.0.0/13\n172.64.0.0/13\n"))
	}))
	defer cfSrv.Close()

	type awsResp struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
		} `json:"prefixes"`
	}
	awsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := awsResp{
			Prefixes: []struct {
				IPPrefix string `json:"ip_prefix"`
			}{
				{IPPrefix: "3.0.0.0/15"},
				{IPPrefix: "52.93.0.0/16"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer awsSrv.Close()

	dir := t.TempDir()
	c := cdn.NewWithBase(cfSrv.URL, awsSrv.URL, dir)

	ctx, err := c.Enrich(context.Background(), model.IOC{Value: "104.16.5.1", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if len(ctx) != 1 {
		t.Fatalf("cloudflare IP: context = %v, want 1 entry", ctx)
	}

	ctx2, err := c.Enrich(context.Background(), model.IOC{Value: "3.0.1.1", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if len(ctx2) != 1 {
		t.Fatalf("AWS IP: context = %v, want 1 entry", ctx2)
	}

	if _, err := os.Stat(filepath.Join(dir, "cdn-prefixes.txt")); err != nil {
		t.Errorf("cache file not written: %v", err)
	}
}

func TestCacheTTL(t *testing.T) {
	cfSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("104.16.0.0/13\n"))
	}))
	defer cfSrv.Close()

	dir := t.TempDir()
	c := cdn.NewWithBase(cfSrv.URL, "", dir)

	_, err := c.Enrich(context.Background(), model.IOC{Value: "104.16.5.1", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}

	c2 := cdn.NewWithBase(cfSrv.URL, "", dir)
	ctx, err := c2.Enrich(context.Background(), model.IOC{Value: "104.16.5.1", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if len(ctx) != 1 {
		t.Errorf("cached lookup: context = %v, want 1 entry", ctx)
	}
}

func TestDownloadFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	c := cdn.NewWithBase(srv.URL, "", dir)

	ctx, err := c.Enrich(context.Background(), model.IOC{Value: "1.2.3.4", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if len(ctx) != 0 {
		t.Errorf("context = %v, want empty on failure", ctx)
	}
}

func TestStaleCache(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "cdn-prefixes.txt")
	os.WriteFile(cachePath, []byte("10.0.0.0/8\tTestProvider\n"), 0o644)

	past := time.Now().Add(-48 * time.Hour)
	os.Chtimes(cachePath, past, past)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := cdn.NewWithBase(srv.URL, "", dir)
	ctx, err := c.Enrich(context.Background(), model.IOC{Value: "10.1.2.3", Type: model.TypeIPv4})
	if err != nil {
		t.Fatal(err)
	}
	if len(ctx) != 1 {
		t.Fatalf("stale cache: context = %v, want 1 entry", ctx)
	}
	if ctx[0] != "Hosted in TestProvider (Cloud Infrastructure)" {
		t.Errorf("stale cache: context = %q, want TestProvider", ctx[0])
	}
}

// Compile-time interface check.
var _ sources.EnrichmentSource = (*cdn.Client)(nil)
