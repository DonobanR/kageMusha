package tranco

import (
	"archive/zip"
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/sources"
)

const (
	defaultBase = "https://tranco-list.eu"
	top100kRank = 100_000
)

// Client implements sources.FPSource for the Tranco top-1M list.
type Client struct {
	base      string
	http      *http.Client
	lowMemory bool
	cacheDir  string

	// mu guards the lazy load/refresh below. Check is called from many
	// goroutines; the first one loads, the rest wait, then all read the
	// (never again written) map without locking. ready flips once.
	mu    sync.Mutex
	ready bool

	// In-memory lookup (default mode). nil in low-memory mode.
	ranks map[string]int
	// Path to the cached CSV on disk (low-memory mode reads from here).
	csvPath string
}

// New creates a production client that caches the list under os.UserCacheDir().
// If lowMemory is true, domains are looked up via linear scan instead of a map.
func New(lowMemory bool) (*Client, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return nil, fmt.Errorf("resolving cache dir: %w", err)
	}
	dir := filepath.Join(base, "kagemusha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating cache dir: %w", err)
	}
	return &Client{
		base:      defaultBase,
		http:      &http.Client{Timeout: 60 * time.Second},
		lowMemory: lowMemory,
		cacheDir:  dir,
		csvPath:   filepath.Join(dir, "tranco-1m.csv"),
	}, nil
}

// NewWithPath creates a test client that reads from a local CSV fixture.
// No network calls, no cache directory.
func NewWithPath(csvPath string, lowMemory bool) *Client {
	return &Client{
		lowMemory: lowMemory,
		csvPath:   csvPath,
	}
}

// NewWithBase creates a client with a custom base URL (for cache download tests).
func NewWithBase(base, cacheDir string, lowMemory bool) *Client {
	return &Client{
		base:      base,
		http:      &http.Client{Timeout: 10 * time.Second},
		lowMemory: lowMemory,
		cacheDir:  cacheDir,
		csvPath:   filepath.Join(cacheDir, "tranco-1m.csv"),
	}
}

func (c *Client) Name() string { return model.SourceTranco }

func (c *Client) AppliesTo(t model.IOCType) bool {
	return t == model.TypeDomain
}

// Check looks up the IOC domain in the Tranco top-1M list.
func (c *Client) Check(ctx context.Context, ioc model.IOC) (sources.FPEvidence, error) {
	if !c.AppliesTo(ioc.Type) {
		return sources.FPEvidence{}, fmt.Errorf("BUG: tranco does not apply to %s", ioc.Type)
	}

	result := sources.FPEvidence{
		Source:  model.SourceTranco,
		Signals: []sources.FPSignal{},
	}

	if err := c.ensureLoaded(ctx); err != nil {
		if ctx.Err() != nil {
			result.Status = model.StatusTimeout
		} else {
			result.Status = model.StatusError
		}
		return result, nil
	}

	rank, found := c.lookupDomain(ioc.Value)
	result.Status = model.StatusOk

	if !found {
		return result, nil
	}

	result.Signals = append(result.Signals, sources.SignalTrancoTop1M)
	if rank <= top100kRank {
		result.Signals = append(result.Signals, sources.SignalTrancoTop100k)
	}
	return result, nil
}

// ensureLoaded guarantees the list is available for lookups.
func (c *Client) ensureLoaded(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ready {
		return nil
	}
	if err := c.loadOrRefresh(ctx); err != nil {
		return err
	}
	c.ready = true
	return nil
}

func (c *Client) loadOrRefresh(ctx context.Context) error {
	// Test path: fixture already on disk, skip cache logic.
	if c.base == "" {
		return c.loadCSV()
	}

	// Production path: check list_id, download if needed.
	if err := c.refreshCache(ctx); err != nil {
		return err
	}
	return c.loadCSV()
}

func (c *Client) loadCSV() error {
	if !c.lowMemory && c.ranks != nil {
		return nil // already loaded
	}
	if c.lowMemory {
		// Low-memory mode: just verify the file exists.
		_, err := os.Stat(c.csvPath)
		return err
	}
	return c.loadMap()
}

func (c *Client) loadMap() error {
	f, err := os.Open(c.csvPath)
	if err != nil {
		return err
	}
	defer f.Close()

	ranks := make(map[string]int, 1_100_000)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		rank, domain, ok := parseLine(line)
		if !ok {
			continue
		}
		ranks[domain] = rank
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	c.ranks = ranks
	return nil
}

// candidateDomains returns the domain followed by its parents, one label at
// a time, most specific first. The walk stops before reaching a public
// suffix (ICANN or private, per the Public Suffix List), so a subdomain of
// a shared-hosting suffix such as evil.github.io or foo.blogspot.com never
// inherits the reputation of the platform itself. For cdn.discordapp.com
// the result is [cdn.discordapp.com, discordapp.com].
func candidateDomains(domain string) []string {
	domain = strings.TrimRight(strings.ToLower(domain), ".")
	var out []string
	for d := domain; d != ""; {
		if suffix, _ := publicsuffix.PublicSuffix(d); suffix == d {
			break
		}
		out = append(out, d)
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
	}
	if len(out) == 0 && domain != "" {
		out = []string{domain} // bare suffix or odd input: exact match only
	}
	return out
}

// lookupDomain returns the rank of the most specific candidate (the domain
// itself, else the nearest listed parent).
func (c *Client) lookupDomain(domain string) (int, bool) {
	cands := candidateDomains(domain)
	if c.lowMemory {
		return c.scanFile(cands)
	}
	for _, d := range cands {
		if rank, ok := c.ranks[d]; ok {
			return rank, true
		}
	}
	return 0, false
}

// scanFile makes a single pass over the CSV and returns the rank of the
// most specific candidate found (cands is ordered most specific first).
func (c *Client) scanFile(cands []string) (int, bool) {
	f, err := os.Open(c.csvPath)
	if err != nil {
		return 0, false
	}
	defer f.Close()

	idx := make(map[string]int, len(cands))
	for i, d := range cands {
		idx[d] = i
	}
	bestIdx, bestRank := len(cands), 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		rank, d, ok := parseLine(scanner.Text())
		if !ok {
			continue
		}
		if i, hit := idx[d]; hit && i < bestIdx {
			bestIdx, bestRank = i, rank
			if i == 0 {
				break
			}
		}
	}
	return bestRank, bestIdx < len(cands)
}

// refreshCache downloads the list if the remote list_id changed.
func (c *Client) refreshCache(ctx context.Context) error {
	remoteID, err := c.fetchListID(ctx)
	if err != nil {
		// If we have a cached CSV, use it despite the check failing.
		if _, statErr := os.Stat(c.csvPath); statErr == nil {
			return nil
		}
		return fmt.Errorf("fetching list ID: %w", err)
	}

	cachedID := c.readCachedListID()
	if cachedID == remoteID {
		if _, err := os.Stat(c.csvPath); err == nil {
			return nil
		}
	}

	fmt.Fprintf(os.Stderr, "Downloading Tranco top-1M list (~9 MB)...\n")
	if err := c.downloadCSV(ctx); err != nil {
		return fmt.Errorf("downloading CSV: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Tranco list cached.\n")

	c.writeCachedListID(remoteID)
	return nil
}

func (c *Client) fetchListID(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/top-1m-id", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET /top-1m-id: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (c *Client) downloadCSV(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/top-1m.csv.zip", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /top-1m.csv.zip: %s", resp.Status)
	}

	// Download ZIP to temp file (archive/zip needs random access).
	tmpZip := c.csvPath + ".zip.tmp"
	f, err := os.Create(tmpZip)
	if err != nil {
		return err
	}

	_, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		os.Remove(tmpZip)
		return copyErr
	}
	if closeErr != nil {
		os.Remove(tmpZip)
		return closeErr
	}
	defer os.Remove(tmpZip)

	return c.extractCSVFromZip(tmpZip)
}

func (c *Client) extractCSVFromZip(zipPath string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("opening zip: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		if f.Name == "top-1m.csv" {
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("opening %s in zip: %w", f.Name, err)
			}
			defer rc.Close()

			tmpCSV := c.csvPath + ".tmp"
			out, err := os.Create(tmpCSV)
			if err != nil {
				return err
			}

			_, copyErr := io.Copy(out, rc)
			closeErr := out.Close()
			if copyErr != nil {
				os.Remove(tmpCSV)
				return copyErr
			}
			if closeErr != nil {
				os.Remove(tmpCSV)
				return closeErr
			}

			return os.Rename(tmpCSV, c.csvPath)
		}
	}

	return fmt.Errorf("top-1m.csv not found in zip archive")
}

func (c *Client) listIDPath() string {
	return filepath.Join(c.cacheDir, "tranco-list-id.txt")
}

func (c *Client) readCachedListID() string {
	data, err := os.ReadFile(c.listIDPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (c *Client) writeCachedListID(id string) {
	os.WriteFile(c.listIDPath(), []byte(id), 0o644)
}

// parseLine splits "rank,domain" and returns (rank, domain, ok).
func parseLine(line string) (int, string, bool) {
	i := strings.IndexByte(line, ',')
	if i < 1 || i >= len(line)-1 {
		return 0, "", false
	}
	rank, err := strconv.Atoi(line[:i])
	if err != nil {
		return 0, "", false
	}
	return rank, strings.ToLower(line[i+1:]), true
}
