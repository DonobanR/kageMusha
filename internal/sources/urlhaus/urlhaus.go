package urlhaus

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/sources"
)

const (
	baseURL        = "https://urlhaus-api.abuse.ch/v1"
	requestTimeout = 10 * time.Second
)

// Client implements sources.ThreatSource for URLhaus.
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

func (c *Client) Name() string { return model.SourceURLhaus }

func (c *Client) AppliesTo(t model.IOCType) bool {
	switch t {
	case model.TypeDomain, model.TypeIPv4, model.TypeURL,
		model.TypeHashMD5, model.TypeHashSHA256:
		return true
	default:
		// SHA-1 and IPv6 not supported by URLhaus API.
		return false
	}
}

// Lookup queries URLhaus for the IOC and returns ThreatEvidence.
// Operational failures are encoded in Status; error is reserved for
// programmer bugs (see sources.ThreatSource contract).
func (c *Client) Lookup(ctx context.Context, ioc model.IOC) (sources.ThreatEvidence, error) {
	if !c.AppliesTo(ioc.Type) {
		return sources.ThreatEvidence{}, fmt.Errorf("BUG: %s does not apply to %s", c.Name(), ioc.Type)
	}

	endpoint, bodyKey, bodyVal := c.resolveEndpoint(ioc)
	result := sources.ThreatEvidence{Source: model.SourceURLhaus}

	body := url.Values{bodyKey: {bodyVal}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		result.Status = model.StatusError
		return result, nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.authKey != "" {
		req.Header.Set("Auth-Key", c.authKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			result.Status = model.StatusTimeout
			result.Extra = "request timeout"
			return result, nil
		}
		// Retry once for transient network errors.
		select {
		case <-ctx.Done():
			result.Status = model.StatusTimeout
			result.Extra = "timeout before retry"
			return result, nil
		case <-time.After(2 * time.Second):
		}
		req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if c.authKey != "" {
			req2.Header.Set("Auth-Key", c.authKey)
		}
		resp, err = c.httpClient.Do(req2)
		if err != nil {
			if ctx.Err() != nil {
				result.Status = model.StatusTimeout
				result.Extra = "timeout on retry"
			} else {
				result.Status = model.StatusError
				result.Extra = fmt.Sprintf("retry failed: %v", err)
			}
			return result, nil
		}
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

	return c.parseResponse(data, ioc.Type, result, c.now())
}

func (c *Client) resolveEndpoint(ioc model.IOC) (endpoint, key, val string) {
	switch ioc.Type {
	case model.TypeDomain, model.TypeIPv4:
		return c.base + "/host/", "host", ioc.Value
	case model.TypeURL:
		return c.base + "/url/", "url", ioc.Value
	case model.TypeHashMD5:
		return c.base + "/payload/", "md5_hash", ioc.Value
	case model.TypeHashSHA256:
		return c.base + "/payload/", "sha256_hash", ioc.Value
	default:
		return c.base + "/host/", "host", ioc.Value
	}
}

func (c *Client) parseResponse(data []byte, iocType model.IOCType, result sources.ThreatEvidence, now time.Time) (sources.ThreatEvidence, error) {
	var raw struct {
		QueryStatus string `json:"query_status"`
		// host endpoint
		URLCount        string         `json:"url_count"`
		URLs            []hostURLEntry `json:"urls"`
		FirstSeen       string         `json:"firstseen"`
		URLhausRef      string         `json:"urlhaus_reference"`
		DateAdded       string         `json:"date_added"`
		URLhausLink     string         `json:"urlhaus_link"`
		PayloadURLhause string         `json:"urlhaus_download"`
		// payload endpoint
		Signature *string `json:"signature"`
		// url endpoint
		Threat string   `json:"threat"`
		Tags   []string `json:"tags"`
		// url endpoint: online state. last_online is null while online or never seen.
		URLStatus  string  `json:"url_status"`
		LastOnline *string `json:"last_online"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		result.Status = model.StatusError
		result.Extra = fmt.Sprintf("parse response: %v", err)
		return result, nil
	}

	switch raw.QueryStatus {
	case "ok":
		// continue
	case "no_results":
		result.Status = model.StatusNotListed
		return result, nil
	default:
		result.Status = model.StatusError
		return result, nil
	}

	result.Status = model.StatusOk

	switch iocType {
	case model.TypeDomain, model.TypeIPv4:
		result.MalwareFamily = extractFamilyFromHostURLs(raw.URLs)
	case model.TypeURL:
		result.MalwareFamily = extractFamilyFromTags(raw.Tags)
	case model.TypeHashMD5, model.TypeHashSHA256:
		if raw.Signature != nil {
			result.MalwareFamily = *raw.Signature
		}
	}

	if ref := raw.URLhausRef; ref != "" {
		result.Reference = ref
	} else if ref := raw.URLhausLink; ref != "" {
		result.Reference = ref
	}

	if ts := raw.FirstSeen; ts != "" {
		result.FirstSeen = normalizeTime(ts)
	} else if ts := raw.DateAdded; ts != "" {
		result.FirstSeen = normalizeTime(ts)
	}

	result.LastSeen = lastSeenFromURLs(raw.URLs, now)
	if result.LastSeen == "" {
		// /url/ endpoint: no urls[] array. Online now → now; else last_online.
		// A null last_online leaves LastSeen empty (decay falls back to FirstSeen).
		if raw.URLStatus == "online" {
			result.LastSeen = now.UTC().Format(time.RFC3339)
		} else if raw.LastOnline != nil && *raw.LastOnline != "" {
			result.LastSeen = normalizeTime(*raw.LastOnline)
		}
	}

	return result, nil
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
	// URLhaus masks the time of day in some fields (real value seen:
	// "2023-10-03 20:XX:XX UTC"). Keep the date, at 00:00 UTC.
	if len(s) >= 10 {
		if t, err := time.Parse("2006-01-02", s[:10]); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return s
}

type hostURLEntry struct {
	Threat    string   `json:"threat"`
	Tags      []string `json:"tags"`
	URLStatus string   `json:"url_status"`
	DateAdded string   `json:"date_added"`
}

func lastSeenFromURLs(urls []hostURLEntry, now time.Time) string {
	for _, u := range urls {
		if u.URLStatus == "online" {
			return now.UTC().Format(time.RFC3339)
		}
	}
	var latest time.Time
	for _, u := range urls {
		if u.DateAdded == "" {
			continue
		}
		for _, layout := range []string{
			"2006-01-02 15:04:05 UTC",
			"2006-01-02 15:04:05",
			"2006-01-02T15:04:05",
		} {
			if t, err := time.Parse(layout, u.DateAdded); err == nil {
				if t.After(latest) {
					latest = t
				}
				break
			}
		}
	}
	if latest.IsZero() {
		return ""
	}
	return latest.UTC().Format(time.RFC3339)
}

func extractFamilyFromHostURLs(urls []hostURLEntry) string {
	for _, u := range urls {
		if f := extractFamilyFromTags(u.Tags); f != "" {
			return f
		}
	}
	return ""
}

// genericTags are URLhaus tags that describe the file format or CPU
// architecture rather than a malware family. Real example: a Mozi URL is
// tagged ["32-bit","elf","mips","Mozi"]; the family is "Mozi".
var genericTags = map[string]struct{}{
	// formats
	"exe": {}, "dll": {}, "elf": {}, "doc": {}, "docx": {}, "xls": {}, "xlsx": {},
	"js": {}, "vbs": {}, "ps1": {}, "sh": {}, "bat": {}, "msi": {}, "lnk": {},
	"zip": {}, "rar": {}, "7z": {}, "gz": {}, "iso": {}, "pdf": {}, "apk": {}, "jar": {},
	// architectures / bitness
	"32-bit": {}, "64-bit": {}, "arm": {}, "arm5": {}, "arm6": {}, "arm7": {}, "arm64": {},
	"aarch64": {}, "mips": {}, "mipsel": {}, "mips64": {}, "x86": {}, "x86-64": {},
	"x64": {}, "amd64": {}, "i386": {}, "i686": {}, "ppc": {}, "powerpc": {},
	"sh4": {}, "m68k": {}, "sparc": {}, "spc": {}, "riscv": {},
}

func extractFamilyFromTags(tags []string) string {
	for _, t := range tags {
		if _, generic := genericTags[strings.ToLower(strings.TrimSpace(t))]; generic {
			continue
		}
		return t
	}
	return ""
}
