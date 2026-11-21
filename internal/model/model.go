package model

// IOCType classifies the indicator. The string value is stable and
// appears in JSON output.
type IOCType string

const (
	TypeDomain     IOCType = "domain"
	TypeIPv4       IOCType = "ipv4"
	TypeIPv6       IOCType = "ipv6"
	TypeURL        IOCType = "url"
	TypeHashMD5    IOCType = "hash_md5"
	TypeHashSHA1   IOCType = "hash_sha1"
	TypeHashSHA256 IOCType = "hash_sha256"
)

// IOC is a single indicator of compromise to evaluate.
type IOC struct {
	Value string
	Type  IOCType
}

// Verdict is the triage outcome. String values are stable API.
type Verdict string

const (
	Malicious  Verdict = "malicious"
	Suspicious Verdict = "suspicious"
	Benign     Verdict = "benign"
	Unknown    Verdict = "unknown"
)

// SourceStatus reflects what a source said about an IOC.
// Codes are stable and part of the JSON API.
type SourceStatus string

const (
	StatusOk          SourceStatus = "ok"
	StatusNotListed   SourceStatus = "not_listed"
	StatusSuppressed  SourceStatus = "suppressed"
	StatusError       SourceStatus = "error"
	StatusRateLimited SourceStatus = "rate_limited"
	StatusTimeout     SourceStatus = "timeout"
)

// SourceResult is one source's response for a single IOC.
type SourceResult struct {
	Name      string       `json:"name"`
	Status    SourceStatus `json:"status"`
	Detail    string       `json:"detail,omitempty"`
	Reference string       `json:"reference,omitempty"`
	FirstSeen string       `json:"first_seen,omitempty"`
	LastSeen  string       `json:"last_seen,omitempty"`
}

// Reason describes what happened, not why the engine decided.
// Code is machine-readable (stable for tests); Message is human-readable
// and exported to STIX description.
type Reason struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Result is the final triage output for one IOC.
type Result struct {
	Target        string         `json:"target"`
	Type          IOCType        `json:"type"`
	Verdict       Verdict        `json:"verdict"`
	Confidence    int            `json:"confidence"`
	FPScore       int            `json:"fp_score"`
	Partial       bool           `json:"partial,omitempty"`
	Historical    bool           `json:"historical,omitempty"`
	FailedSources []string       `json:"failed_sources,omitempty"`
	Context       []string       `json:"context,omitempty"`
	Reasons       []Reason       `json:"reasons"`
	Sources       []SourceResult `json:"sources"`
	STIXID        string         `json:"stix_id,omitempty"`
}
