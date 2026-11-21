package feodo

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/sources"
)

const (
	defaultURL       = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
	cacheTTL         = 24 * time.Hour
	cacheFile        = "feodo-ipblocklist.csv"
	staleWarningDays = 7
)

type entry struct {
	FirstSeen  string
	DstPort    string
	C2Status   string
	LastOnline string
	Malware    string
}

// Client implements sources.ThreatSource for Feodo Tracker.
// It downloads a CSV blocklist of confirmed C2 IPs and does local lookup.
type Client struct {
	httpClient *http.Client
	url        string
	csvPath    string
	mu         sync.Mutex
	ips        map[string]entry
	csvAge     time.Duration // age of the CSV file at load time
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
		httpClient: &http.Client{Timeout: 30 * time.Second},
		url:        defaultURL,
		csvPath:    filepath.Join(dir, cacheFile),
	}, nil
}

// NewWithBase creates a client with a custom URL and cache dir (for download tests).
func NewWithBase(url, cacheDir string) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		url:        url,
		csvPath:    filepath.Join(cacheDir, cacheFile),
	}
}

// NewWithPath creates a test client from a local fixture. No network.
func NewWithPath(csvPath string) *Client {
	c := &Client{csvPath: csvPath}
	f, err := os.Open(csvPath)
	if err != nil {
		return c
	}
	defer f.Close()
	c.ips, c.csvAge = parseCSV(f, time.Now())
	return c
}

func (c *Client) Name() string { return model.SourceFeodo }

func (c *Client) AppliesTo(t model.IOCType) bool {
	return t == model.TypeIPv4
}

func (c *Client) Lookup(ctx context.Context, ioc model.IOC) (sources.ThreatEvidence, error) {
	if !c.AppliesTo(ioc.Type) {
		return sources.ThreatEvidence{}, fmt.Errorf("BUG: feodo does not apply to %s", ioc.Type)
	}

	if err := c.ensure(ctx); err != nil {
		return sources.ThreatEvidence{Source: model.SourceFeodo, Status: model.StatusError}, nil
	}

	if e, ok := c.ips[ioc.Value]; ok {
		ev := sources.ThreatEvidence{
			Source:        model.SourceFeodo,
			Status:        model.StatusOk,
			MalwareFamily: e.Malware,
			Reference:     "https://feodotracker.abuse.ch/browse/host/" + ioc.Value + "/",
		}
		if e.FirstSeen != "" {
			ev.FirstSeen = normalizeTime(e.FirstSeen)
		}
		if e.LastOnline != "" {
			ev.LastSeen = normalizeTime(e.LastOnline)
		}
		extra := ""
		if e.DstPort != "" || e.C2Status != "" {
			extra = fmt.Sprintf("C2 port %s, status %s", e.DstPort, e.C2Status)
		}
		if staleDays := int(c.csvAge.Hours() / 24); staleDays >= staleWarningDays {
			warn := fmt.Sprintf("CSV is %d days old", staleDays)
			if extra != "" {
				extra += " | " + warn
			} else {
				extra = warn
			}
		}
		ev.Extra = extra
		return ev, nil
	}
	return sources.ThreatEvidence{Source: model.SourceFeodo, Status: model.StatusNotListed}, nil
}

func (c *Client) ensure(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ips != nil {
		return nil
	}

	if c.cacheIsFresh() {
		return c.loadFromDisk()
	}

	if c.url == "" {
		return c.loadFromDisk()
	}

	if err := c.download(ctx); err != nil {
		if c.loadFromDisk() == nil {
			return nil
		}
		return err
	}
	return c.loadFromDisk()
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
	c.ips, c.csvAge = parseCSV(f, time.Now())
	if staleDays := int(c.csvAge.Hours() / 24); staleDays >= staleWarningDays {
		fmt.Fprintf(os.Stderr, "warning: feodo CSV is %d days old; results may be incomplete\n", staleDays)
	}
	return nil
}

func (c *Client) download(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("feodo download: HTTP %d", resp.StatusCode)
	}

	dir := filepath.Dir(c.csvPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, "feodo-*.csv")
	if err != nil {
		return err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmp.Name(), c.csvPath)
}

func normalizeTime(s string) string {
	for _, layout := range []string{
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return s
}

// parseCSV reads the Feodo CSV and returns entries plus the content age
// derived from the "# Last updated:" header line. If the header is missing
// or unparseable, age is zero (no staleness warning).
func parseCSV(r io.Reader, now time.Time) (map[string]entry, time.Duration) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, 0
	}

	contentAge := parseLastUpdated(data, now)

	ips := make(map[string]entry)
	cr := csv.NewReader(strings.NewReader(string(data)))
	cr.Comment = '#'
	cr.FieldsPerRecord = -1

	header := true
	for {
		record, err := cr.Read()
		if err != nil {
			break
		}
		if header {
			header = false
			continue
		}
		if len(record) < 6 {
			continue
		}
		ip := record[1]
		firstSeen := record[0]
		dstPort := record[2]
		malware := record[5]
		c2Status := record[3]
		lastOnline := record[4]
		ips[ip] = entry{FirstSeen: firstSeen, DstPort: dstPort, C2Status: c2Status, LastOnline: lastOnline, Malware: malware}
	}
	return ips, contentAge
}

func parseLastUpdated(data []byte, now time.Time) time.Duration {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "#") {
			break
		}
		if after, ok := strings.CutPrefix(line, "# Last updated:"); ok {
			after = strings.TrimRight(strings.TrimSpace(after), " #")
			if t, err := time.Parse("2006-01-02 15:04:05 UTC", after); err == nil {
				return now.Sub(t)
			}
		}
	}
	return 0
}
