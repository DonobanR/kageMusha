package cdn

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DonobanR/kagemusha/internal/model"
)

const (
	cloudflareV4URL = "https://www.cloudflare.com/ips-v4"
	awsURL          = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	cacheTTL        = 24 * time.Hour
	cacheFile       = "cdn-prefixes.txt"
)

type taggedPrefix struct {
	Prefix   netip.Prefix
	Provider string
}

// Client implements sources.EnrichmentSource for CDN/Cloud IP ranges.
// It downloads official CIDR lists from Cloudflare and AWS, caches
// them locally, and reports which cloud provider hosts a given IP.
// This is context for the analyst, NOT evidence for the verdict.
type Client struct {
	httpClient *http.Client
	cfURL      string
	awsURL     string
	csvPath    string
	prefixes   []taggedPrefix
}

// New creates a production client that caches under os.UserCacheDir().
func New() (*Client, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("resolving cache dir: %w", err)
	}
	dir := filepath.Join(base, "kagemusha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating cache dir: %w", err)
	}
	return &Client{
		httpClient: &http.Client{Timeout: 60 * time.Second},
		cfURL:      cloudflareV4URL,
		awsURL:     awsURL,
		csvPath:    filepath.Join(dir, cacheFile),
	}, nil
}

// NewWithBase creates a client with custom URLs and cache dir (for tests).
func NewWithBase(cfURL, awsURL, cacheDir string) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cfURL:      cfURL,
		awsURL:     awsURL,
		csvPath:    filepath.Join(cacheDir, cacheFile),
	}
}

// NewWithCIDRs creates a test client from pre-parsed CIDRs tagged to a provider.
func NewWithCIDRs(provider string, cidrs []string) *Client {
	c := &Client{}
	for _, s := range cidrs {
		if p, err := netip.ParsePrefix(s); err == nil {
			c.prefixes = append(c.prefixes, taggedPrefix{Prefix: p, Provider: provider})
		}
	}
	return c
}

func (c *Client) Name() string { return model.SourceCDN }

func (c *Client) AppliesTo(t model.IOCType) bool {
	return t == model.TypeIPv4
}

// Enrich returns context strings if the IP belongs to a known cloud
// provider. Returns nil (no context) if the IP is not in any range.
// This does NOT affect the score — it's data for the analyst.
func (c *Client) Enrich(ctx context.Context, ioc model.IOC) ([]string, error) {
	if !c.AppliesTo(ioc.Type) {
		return nil, fmt.Errorf("BUG: cdn does not apply to %s", ioc.Type)
	}

	if err := c.ensure(ctx); err != nil {
		return nil, nil
	}

	addr, err := netip.ParseAddr(ioc.Value)
	if err != nil {
		return nil, nil
	}

	for _, tp := range c.prefixes {
		if tp.Prefix.Contains(addr) {
			return []string{
				fmt.Sprintf("Hosted in %s (Cloud Infrastructure)", tp.Provider),
			}, nil
		}
	}

	return nil, nil
}

func (c *Client) ensure(ctx context.Context) error {
	if c.prefixes != nil {
		return nil
	}

	if c.cacheIsFresh() {
		return c.loadFromDisk()
	}

	if c.cfURL == "" && c.awsURL == "" {
		return c.loadFromDisk()
	}

	if err := c.downloadAndCache(ctx); err != nil {
		if c.loadFromDisk() == nil {
			return nil
		}
		return err
	}
	return nil
}

func (c *Client) cacheIsFresh() bool {
	info, err := os.Stat(c.csvPath)
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) < cacheTTL
}

func (c *Client) loadFromDisk() error {
	f, err := os.Open(c.csvPath)
	if err != nil {
		return err
	}
	defer f.Close()
	c.prefixes = parsePrefixList(f)
	return nil
}

func (c *Client) downloadAndCache(ctx context.Context) error {
	var all []taggedPrefix

	if c.cfURL != "" {
		cidrs, err := c.fetchText(ctx, c.cfURL, "Cloudflare")
		if err != nil {
			return fmt.Errorf("cloudflare: %w", err)
		}
		all = append(all, cidrs...)
	}

	if c.awsURL != "" {
		cidrs, err := c.fetchAWS(ctx, c.awsURL)
		if err != nil {
			return fmt.Errorf("aws: %w", err)
		}
		all = append(all, cidrs...)
	}

	if err := c.saveToDisk(all); err != nil {
		return err
	}

	c.prefixes = all
	return nil
}

func (c *Client) fetchText(ctx context.Context, url, provider string) ([]taggedPrefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var prefixes []taggedPrefix
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if p, err := netip.ParsePrefix(line); err == nil {
			prefixes = append(prefixes, taggedPrefix{Prefix: p, Provider: provider})
		}
	}
	return prefixes, sc.Err()
}

func (c *Client) fetchAWS(ctx context.Context, url string) ([]taggedPrefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var data struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
		} `json:"prefixes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	var prefixes []taggedPrefix
	for _, e := range data.Prefixes {
		if p, err := netip.ParsePrefix(e.IPPrefix); err == nil {
			prefixes = append(prefixes, taggedPrefix{Prefix: p, Provider: "AWS"})
		}
	}
	return prefixes, nil
}

func (c *Client) saveToDisk(prefixes []taggedPrefix) error {
	dir := filepath.Dir(c.csvPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, "cdn-*.txt")
	if err != nil {
		return err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()

	w := bufio.NewWriter(tmp)
	for _, tp := range prefixes {
		fmt.Fprintf(w, "%s\t%s\n", tp.Prefix.String(), tp.Provider)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmp.Name(), c.csvPath)
}

func parsePrefixList(r io.Reader) []taggedPrefix {
	var prefixes []taggedPrefix
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		cidr := parts[0]
		provider := "Unknown"
		if len(parts) == 2 {
			provider = parts[1]
		}
		if p, err := netip.ParsePrefix(cidr); err == nil {
			prefixes = append(prefixes, taggedPrefix{Prefix: p, Provider: provider})
		}
	}
	return prefixes
}
