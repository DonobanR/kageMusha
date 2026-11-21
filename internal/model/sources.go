package model

// Source name constants. Shared between sources/ (who produces them)
// and scoring/ (who consumes them). Living here avoids a circular
// dependency between the two packages.
const (
	SourceURLhaus   = "urlhaus"
	SourceThreatFox = "threatfox"
	SourceOTX       = "otx"
	SourceFeodo     = "feodo"
	SourceTranco    = "tranco"
	SourceCDN       = "cdn"
	SourceTor       = "tor"
)
