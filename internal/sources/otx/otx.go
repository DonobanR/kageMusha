package otx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/sources"
)

const (
	defaultBase    = "https://otx.alienvault.com"
	requestTimeout = 30 * time.Second
)

// Client implements sources.ThreatSource for AlienVault OTX.
type Client struct {
	http   *http.Client
	apiKey string
	base   string
}

func New(apiKey string) *Client {
	return &Client{
		http:   &http.Client{Timeout: requestTimeout},
		apiKey: apiKey,
		base:   defaultBase,
	}
}

func NewWithBase(base, apiKey string) *Client {
	return &Client{
		http:   &http.Client{Timeout: requestTimeout},
		apiKey: apiKey,
		base:   base,
	}
}

func (c *Client) Name() string { return model.SourceOTX }

func (c *Client) AppliesTo(t model.IOCType) bool {
	switch t {
	case model.TypeIPv4, model.TypeIPv6, model.TypeDomain, model.TypeURL,
		model.TypeHashMD5, model.TypeHashSHA1, model.TypeHashSHA256:
		return true
	default:
		return false
	}
}

func (c *Client) Lookup(ctx context.Context, ioc model.IOC) (sources.ThreatEvidence, error) {
	if !c.AppliesTo(ioc.Type) {
		return sources.ThreatEvidence{}, fmt.Errorf("BUG: %s does not apply to %s", c.Name(), ioc.Type)
	}

	result := sources.ThreatEvidence{Source: model.SourceOTX}

	endpoint := c.base + apiPath(ioc)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		result.Status = model.StatusError
		return result, nil
	}
	if c.apiKey != "" {
		req.Header.Set("X-OTX-API-KEY", c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			result.Status = model.StatusTimeout
			result.Extra = "request timeout"
			return result, nil
		}
		// Retry once on timeout or transient error
		select {
		case <-ctx.Done():
			result.Status = model.StatusTimeout
			result.Extra = "timeout before retry"
			return result, nil
		case <-time.After(2 * time.Second):
		}
		req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if c.apiKey != "" {
			req2.Header.Set("X-OTX-API-KEY", c.apiKey)
		}
		resp, err = c.http.Do(req2)
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

	if resp.StatusCode == http.StatusTooManyRequests {
		resp.Body.Close()
		wait := retryAfter(resp.Header.Get("Retry-After"))
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if wait > remaining {
				result.Status = model.StatusRateLimited
				return result, nil
			}
		}
		select {
		case <-ctx.Done():
			result.Status = model.StatusTimeout
			return result, nil
		case <-time.After(wait):
		}
		req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if c.apiKey != "" {
			req2.Header.Set("X-OTX-API-KEY", c.apiKey)
		}
		resp, err = c.http.Do(req2)
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
		result.Extra = "rate limited after retry"
		return result, nil
	}
	if resp.StatusCode == http.StatusForbidden {
		result.Status = model.StatusError
		result.Extra = "HTTP 403 forbidden (check API key)"
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

	return parseResponse(data, result)
}

func apiPath(ioc model.IOC) string {
	switch ioc.Type {
	case model.TypeIPv4:
		return "/api/v1/indicators/IPv4/" + ioc.Value + "/general"
	case model.TypeIPv6:
		return "/api/v1/indicators/IPv6/" + ioc.Value + "/general"
	case model.TypeDomain:
		return "/api/v1/indicators/domain/" + ioc.Value + "/general"
	case model.TypeURL:
		return "/api/v1/indicators/url/" + ioc.Value + "/general"
	case model.TypeHashMD5, model.TypeHashSHA1, model.TypeHashSHA256:
		return "/api/v1/indicators/file/" + ioc.Value + "/general"
	default:
		return "/api/v1/indicators/file/" + ioc.Value + "/general"
	}
}

type apiResponse struct {
	Validation []validation `json:"validation"`
	PulseInfo  pulseInfo    `json:"pulse_info"`
}

type validation struct {
	Source string `json:"source"`
	Name   string `json:"name"`
}

type pulseInfo struct {
	Count  int     `json:"count"`
	Pulses []pulse `json:"pulses"`
}

type pulse struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Tags            []string `json:"tags"`
	Created         string   `json:"created"`
	Modified        string   `json:"modified"`
	MalwareFamilies []family `json:"malware_families"`
}

// family handles OTX's two malware_families formats:
//   - string: "Mirai"
//   - object: {"id":"Mirai (ELF)","display_name":"Mirai (ELF)","target":null}
type family struct{ Name string }

func (f *family) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		f.Name = s
		return nil
	}
	var o struct {
		DisplayName string `json:"display_name"`
	}
	_ = json.Unmarshal(b, &o)
	f.Name = o.DisplayName
	return nil
}

func parseResponse(data []byte, result sources.ThreatEvidence) (sources.ThreatEvidence, error) {
	var resp apiResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		result.Status = model.StatusError
		result.Extra = fmt.Sprintf("parse response: %v", err)
		return result, nil
	}

	if resp.PulseInfo.Count == 0 {
		result.Status = model.StatusNotListed
		return result, nil
	}

	if benign := benignValidation(resp.Validation); benign != "" {
		result.Status = model.StatusSuppressed
		result.Extra = fmt.Sprintf("%d pulse(s) ignored: %s",
			resp.PulseInfo.Count, benign)
		return result, nil
	}

	result.Status = model.StatusOk

	pulses := resp.PulseInfo.Pulses
	if len(pulses) > 0 {
		var oldest, latest time.Time
		var newestPulse *pulse
		var newestCreated time.Time

		for i := range pulses {
			p := &pulses[i]
			created := parseTime(p.Created)
			if !created.IsZero() {
				if oldest.IsZero() || created.Before(oldest) {
					oldest = created
				}
				if created.After(latest) {
					latest = created
				}
				if newestPulse == nil || created.After(newestCreated) {
					newestPulse = p
					newestCreated = created
				}
			}
			// Modified is intentionally NOT used for latest: a pulse
			// modified today doesn't mean the IOC was seen today.
		}

		if newestPulse != nil && newestPulse.ID != "" {
			result.Reference = "https://otx.alienvault.com/pulse/" + newestPulse.ID
		}
		if !oldest.IsZero() {
			result.FirstSeen = oldest.UTC().Format(time.RFC3339)
		}
		if !latest.IsZero() && !latest.Equal(oldest) {
			result.LastSeen = latest.UTC().Format(time.RFC3339)
		}

		result.MalwareFamily = extractFamily(pulses)
		if result.MalwareFamily == "" {
			result.Extra = fmt.Sprintf("%d pulse(s)", resp.PulseInfo.Count)
		}
	}
	return result, nil
}

func parseTime(s string) time.Time {
	for _, layout := range []string{
		"2006-01-02T15:04:05.000000",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func normalizeTime(s string) string {
	if t := parseTime(s); !t.IsZero() {
		return t.Format(time.RFC3339)
	}
	return s
}

// benignValidation returns a human-readable label if the validation
// entries prove the IOC is benign (explicit whitelist or domain
// popularity). Returns "" if no entry warrants suppression.
//
// "Cloud Provider IP range" is intentionally NOT treated as benign:
// cloud ranges are multi-tenant, and C2 infrastructure routinely
// lives on rented VPS instances in AWS, Azure, DigitalOcean, etc.
func benignValidation(entries []validation) string {
	for _, v := range entries {
		if isBenignSource(v.Source) {
			return v.Name
		}
	}
	return ""
}

var benignSources = map[string]bool{
	"whitelist":      true,
	"false_positive": true,
	"akamai":         true,
	"alexa":          true,
	"majestic":       true,
}

func isBenignSource(source string) bool {
	return benignSources[strings.ToLower(source)]
}

func retryAfter(header string) time.Duration {
	if header == "" {
		return 2 * time.Second
	}
	if secs, err := strconv.Atoi(header); err == nil && secs > 0 {
		if secs > 30 {
			secs = 30
		}
		return time.Duration(secs) * time.Second
	}
	return 2 * time.Second
}

func extractFamily(pulses []pulse) string {
	counts := make(map[string]int)
	for _, p := range pulses {
		seen := make(map[string]bool)
		for _, f := range p.MalwareFamilies {
			if f.Name == "" {
				continue
			}
			key := strings.ToLower(f.Name)
			if !seen[key] {
				seen[key] = true
				counts[key]++
			}
		}
	}
	if len(counts) == 0 {
		return ""
	}
	var best string
	var bestCount int
	for name, count := range counts {
		if count > bestCount {
			best = name
			bestCount = count
		}
	}
	// No clear winner: top family appears in fewer than 2 pulses
	// and there are other families competing.
	if bestCount < 2 && len(counts) > 1 {
		return ""
	}
	// Return the original-case version from the first matching pulse.
	for _, p := range pulses {
		for _, f := range p.MalwareFamilies {
			if strings.ToLower(f.Name) == best {
				return f.Name
			}
		}
	}
	return ""
}
