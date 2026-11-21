package threatfox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/sources"
)

const (
	baseURL        = "https://threatfox-api.abuse.ch/api/v1/"
	requestTimeout = 10 * time.Second
)

// Client implements sources.ThreatSource for ThreatFox.
type Client struct {
	httpClient *http.Client
	authKey    string
	base       string
	clock      func() time.Time
}

func (c *Client) now() time.Time {
	if c.clock != nil {
		return c.clock()
	}
	return time.Now()
}

func New(authKey string) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: requestTimeout},
		authKey:    authKey,
		base:       baseURL,
	}
}

// NewWithBase creates a client with a custom base URL (for testing).
func NewWithBase(base, authKey string) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: requestTimeout},
		authKey:    authKey,
		base:       base,
	}
}

// NewWithBaseClock creates a client with a custom base URL and clock (for testing).
func NewWithBaseClock(base, authKey string, clock func() time.Time) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: requestTimeout},
		authKey:    authKey,
		base:       base,
		clock:      clock,
	}
}

func (c *Client) Name() string { return model.SourceThreatFox }

func (c *Client) AppliesTo(t model.IOCType) bool {
	switch t {
	case model.TypeDomain, model.TypeIPv4, model.TypeURL,
		model.TypeHashMD5, model.TypeHashSHA256:
		return true
	default:
		return false
	}
}

// Lookup queries ThreatFox for the IOC and returns ThreatEvidence.
// Operational failures are encoded in Status; error is reserved for
// programmer bugs (see sources.ThreatSource contract).
func (c *Client) Lookup(ctx context.Context, ioc model.IOC) (sources.ThreatEvidence, error) {
	if !c.AppliesTo(ioc.Type) {
		return sources.ThreatEvidence{}, fmt.Errorf("BUG: %s does not apply to %s", c.Name(), ioc.Type)
	}

	result := sources.ThreatEvidence{Source: model.SourceThreatFox}

	payload, err := json.Marshal(buildRequest(ioc))
	if err != nil {
		result.Status = model.StatusError
		return result, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base, bytes.NewReader(payload))
	if err != nil {
		result.Status = model.StatusError
		return result, nil
	}
	req.Header.Set("Content-Type", "application/json")
	if c.authKey != "" {
		req.Header.Set("Auth-Key", c.authKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			result.Status = model.StatusTimeout
			result.Extra = "request timeout"
		} else {
			result.Status = model.StatusError
			result.Extra = fmt.Sprintf("request failed: %v", err)
		}
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		result.Status = model.StatusRateLimited
		result.Extra = "rate limited"
		return result, nil
	}

	if resp.StatusCode != http.StatusOK {
		result.Status = model.StatusError
		result.Extra = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return result, nil
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		result.Status = model.StatusError
		result.Extra = fmt.Sprintf("read body: %v", err)
		return result, nil
	}

	return parseResponse(data, result, ioc.Value, ioc.Type, c.now())
}

type apiRequest struct {
	Query      string `json:"query"`
	SearchTerm string `json:"search_term"`
}

func buildRequest(ioc model.IOC) apiRequest {
	return apiRequest{Query: "search_ioc", SearchTerm: ioc.Value}
}

type apiResponse struct {
	QueryStatus string          `json:"query_status"`
	Data        json.RawMessage `json:"data"`
}

type iocEntry struct {
	ID              string  `json:"id"`
	IOC             string  `json:"ioc"`
	IOCType         string  `json:"ioc_type"`
	Malware         string  `json:"malware_printable"`
	ThreatType      string  `json:"threat_type"`
	ConfidenceLevel int     `json:"confidence_level"`
	Reporter        string  `json:"reporter"`
	FirstSeen       string  `json:"first_seen"`
	LastSeen        *string `json:"last_seen"`
}

func isAnchorGrade(e iocEntry) bool {
	return e.Reporter == "abuse_ch" && e.ThreatType == "botnet_cc"
}

func parseResponse(data []byte, result sources.ThreatEvidence, queriedIOC string, iocType model.IOCType, now time.Time) (sources.ThreatEvidence, error) {
	var raw apiResponse
	if err := json.Unmarshal(data, &raw); err != nil {
		result.Status = model.StatusError
		return result, nil
	}

	switch raw.QueryStatus {
	case "ok":
		// continue to parse data
	case "no_results", "no_result":
		result.Status = model.StatusNotListed
		return result, nil
	default:
		result.Status = model.StatusError
		return result, nil
	}

	var entries []iocEntry
	if err := json.Unmarshal(raw.Data, &entries); err != nil {
		result.Status = model.StatusNotListed
		return result, nil
	}

	if len(entries) == 0 {
		result.Status = model.StatusNotListed
		return result, nil
	}

	// ThreatFox search_ioc does substring matching, so "google.com"
	// can return URLs like "http://evil.tld/google.com/shell.php".
	// Match by host identity, not raw string:
	//   - IP query matches "ip:port" entries with the same IP
	//   - Domain query matches domain entries and URL entries whose host is that domain
	q := strings.ToLower(strings.TrimRight(queriedIOC, "."))
	match, anchorFresh := bestHostMatch(entries, queriedIOC, iocType, now)
	if match == nil {
		result.Status = model.StatusNotListed
		return result, nil
	}

	result.Status = model.StatusOk
	result.MalwareFamily = match.Malware
	result.Anchor = anchorFresh
	if match.ID != "" {
		result.Reference = "https://threatfox.abuse.ch/ioc/" + match.ID
	}
	if match.FirstSeen != "" {
		result.FirstSeen = normalizeTime(match.FirstSeen)
	}
	if match.LastSeen != nil && *match.LastSeen != "" {
		result.LastSeen = normalizeTime(*match.LastSeen)
	}

	if families := collectFamilies(entries, q, match.Malware); families != "" {
		result.Extra = families
	}
	return result, nil
}

// anchorMaxAge returns the maximum age for an anchor entry to get preference,
// based on IOC type. Matches the scoring half-lives: 30 days for IPs,
// 90 days for domains/URLs. Hashes have no age concept so get 0.
func anchorMaxAge(iocType model.IOCType) time.Duration {
	switch iocType {
	case model.TypeIPv4, model.TypeIPv6:
		return 30 * 24 * time.Hour
	case model.TypeDomain, model.TypeURL:
		return 90 * 24 * time.Hour
	default:
		return 0
	}
}

// bestHostMatch selects the best matching entry. An anchor-grade entry
// is preferred only if it is recent (within anchorMaxAge for the IOC type).
// Otherwise the most recent entry wins, regardless of anchor grade.
// Returns the matched entry and whether it qualifies as a fresh anchor.
func bestHostMatch(entries []iocEntry, queried string, iocType model.IOCType, now time.Time) (*iocEntry, bool) {
	q := strings.ToLower(strings.TrimRight(queried, "."))
	maxAge := anchorMaxAge(iocType)

	var bestAnchor *iocEntry
	var bestAnchorTime time.Time
	var bestRecent *iocEntry
	var bestRecentTime time.Time

	for i := range entries {
		if !iocMatchesQuery(entries[i].IOC, q) {
			continue
		}
		t := entryTime(entries[i])
		if bestRecent == nil || t.After(bestRecentTime) {
			bestRecent = &entries[i]
			bestRecentTime = t
		}
		if maxAge > 0 && isAnchorGrade(entries[i]) && !t.IsZero() && now.Sub(t) <= maxAge {
			if bestAnchor == nil || t.After(bestAnchorTime) {
				bestAnchor = &entries[i]
				bestAnchorTime = t
			}
		}
	}

	if bestAnchor != nil {
		return bestAnchor, true
	}
	return bestRecent, false
}

// collectFamilies returns a summary of all distinct malware families across
// matching entries, excluding the primary family already in MalwareFamily.
func collectFamilies(entries []iocEntry, query, primary string) string {
	seen := map[string]struct{}{}
	if primary != "" {
		seen[strings.ToLower(primary)] = struct{}{}
	}
	var others []string
	for _, e := range entries {
		if !iocMatchesQuery(e.IOC, query) {
			continue
		}
		f := e.Malware
		if f == "" {
			continue
		}
		key := strings.ToLower(f)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		others = append(others, f)
	}
	if len(others) == 0 {
		return ""
	}
	return "also: " + strings.Join(others, ", ")
}

func entryTime(e iocEntry) time.Time {
	if e.LastSeen != nil && *e.LastSeen != "" {
		for _, layout := range []string{
			"2006-01-02 15:04:05 UTC",
			"2006-01-02 15:04:05",
		} {
			if t, err := time.Parse(layout, *e.LastSeen); err == nil {
				return t.UTC()
			}
		}
	}
	if e.FirstSeen != "" {
		for _, layout := range []string{
			"2006-01-02 15:04:05 UTC",
			"2006-01-02 15:04:05",
		} {
			if t, err := time.Parse(layout, e.FirstSeen); err == nil {
				return t.UTC()
			}
		}
	}
	return time.Time{}
}

// iocMatchesQuery checks whether a ThreatFox IOC entry refers to the
// queried host. Handles three ThreatFox storage formats:
//
//	"ip:port"          → strip port, compare IP
//	"http://host/..."  → extract host from URL, compare domain
//	"domain"           → direct comparison
func iocMatchesQuery(ioc, query string) bool {
	ioc = strings.ToLower(strings.TrimRight(ioc, "."))

	// Direct match (domain or hash)
	if ioc == query {
		return true
	}

	// ip:port — ThreatFox stores most network IOCs this way
	if host, _, ok := strings.Cut(ioc, ":"); ok {
		if host == query {
			return true
		}
	}

	// URL — extract host and compare
	if strings.HasPrefix(ioc, "http://") || strings.HasPrefix(ioc, "https://") {
		if h := urlHost(ioc); h == query {
			return true
		}
	}

	return false
}

func urlHost(raw string) string {
	// Strip scheme
	after := raw
	if i := strings.Index(raw, "://"); i >= 0 {
		after = raw[i+3:]
	}
	// Strip path
	if i := strings.IndexByte(after, '/'); i >= 0 {
		after = after[:i]
	}
	// Strip port
	if i := strings.LastIndexByte(after, ':'); i >= 0 {
		after = after[:i]
	}
	// Strip trailing dot
	return strings.TrimRight(after, ".")
}

func normalizeTime(s string) string {
	for _, layout := range []string{
		"2006-01-02 15:04:05 UTC",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return s
}
