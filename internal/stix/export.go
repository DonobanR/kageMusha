package stix

import (
	"crypto/sha1"
	"fmt"
	"strings"
	"time"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/scoring"
)

const stixTimeFormat = "2006-01-02T15:04:05.000Z"

// Fixed namespace UUID for deterministic STIX IDs (ASCII: "kagemusha-stix-1").
var nsKagemusha = [16]byte{
	0x6b, 0x61, 0x67, 0x65, 0x6d, 0x75, 0x73, 0x68,
	0x61, 0x2d, 0x73, 0x74, 0x69, 0x78, 0x2d, 0x31,
}

// Bundle is the STIX 2.1 top-level container.
type Bundle struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Objects []any  `json:"objects"`
}

// ExternalReference is a STIX 2.1 external-reference entry.
type ExternalReference struct {
	SourceName  string `json:"source_name"`
	URL         string `json:"url,omitempty"`
	Description string `json:"description,omitempty"`
}

// Indicator represents a STIX 2.1 Indicator SDO.
type Indicator struct {
	Type               string              `json:"type"`
	SpecVersion        string              `json:"spec_version"`
	ID                 string              `json:"id"`
	Created            string              `json:"created"`
	Modified           string              `json:"modified"`
	Name               string              `json:"name"`
	Description        string              `json:"description"`
	Pattern            string              `json:"pattern"`
	PatternType        string              `json:"pattern_type"`
	ValidFrom          string              `json:"valid_from"`
	IndicatorTypes     []string            `json:"indicator_types"`
	Confidence         int                 `json:"confidence"`
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
}

// Malware represents a STIX 2.1 Malware SDO.
type Malware struct {
	Type         string   `json:"type"`
	SpecVersion  string   `json:"spec_version"`
	ID           string   `json:"id"`
	Created      string   `json:"created"`
	Modified     string   `json:"modified"`
	Name         string   `json:"name"`
	IsFamily     bool     `json:"is_family"`
	MalwareTypes []string `json:"malware_types"`
}

// Relationship represents a STIX 2.1 Relationship SRO.
type Relationship struct {
	Type             string `json:"type"`
	SpecVersion      string `json:"spec_version"`
	ID               string `json:"id"`
	Created          string `json:"created"`
	Modified         string `json:"modified"`
	RelationshipType string `json:"relationship_type"`
	SourceRef        string `json:"source_ref"`
	TargetRef        string `json:"target_ref"`
}

// FilterActionable returns only the results that are actionable threat
// intelligence suitable for SIEM import. Excludes:
//   - benign and unknown results (no threat signal)
//   - suspicious results with FP score >= veto threshold (e.g. github.com
//     in Tranco Top 100k — suspicious from a low-weight threat source but
//     almost certainly a false positive)
//   - historical results (anchor floor kept verdict at suspicious but all
//     evidence is old — the IP is likely reassigned)
func FilterActionable(results []model.Result) (actionable []model.Result, skipped int) {
	for _, r := range results {
		switch {
		case r.Historical:
			skipped++
		case r.Verdict == model.Malicious:
			actionable = append(actionable, r)
		case r.Verdict == model.Suspicious && r.FPScore < scoring.FPVetoThreshold:
			actionable = append(actionable, r)
		default:
			skipped++
		}
	}
	return
}

// ToBundle converts scan results into a STIX 2.1 Bundle.
// All results are included. For STIX export to SIEMs, pre-filter
// with FilterActionable to exclude benign/unknown IOCs.
// The same inputs always produce the same IDs (UUID v5).
func ToBundle(results []model.Result, now time.Time) Bundle {
	ts := now.UTC().Format(stixTimeFormat)
	var objects []any
	malwareIDs := make(map[string]string)

	for _, r := range results {
		indID := newID("indicator", r.Target)
		objects = append(objects, Indicator{
			Type:               "indicator",
			SpecVersion:        "2.1",
			ID:                 indID,
			Created:            ts,
			Modified:           ts,
			Name:               r.Target,
			Description:        description(r),
			Pattern:            Pattern(r.Type, r.Target),
			PatternType:        "stix",
			ValidFrom:          ts,
			IndicatorTypes:     indicatorTypes(r.Verdict),
			Confidence:         r.Confidence,
			ExternalReferences: externalRefs(r),
		})

		for _, family := range families(r) {
			malID, exists := malwareIDs[family]
			if !exists {
				malID = newID("malware", family)
				objects = append(objects, Malware{
					Type:         "malware",
					SpecVersion:  "2.1",
					ID:           malID,
					Created:      ts,
					Modified:     ts,
					Name:         family,
					IsFamily:     true,
					MalwareTypes: []string{"unknown"},
				})
				malwareIDs[family] = malID
			}
			objects = append(objects, Relationship{
				Type:             "relationship",
				SpecVersion:      "2.1",
				ID:               newID("relationship", indID+":"+malID),
				Created:          ts,
				Modified:         ts,
				RelationshipType: "indicates",
				SourceRef:        indID,
				TargetRef:        malID,
			})
		}
	}

	var names []string
	for _, r := range results {
		names = append(names, r.Target)
	}

	return Bundle{
		Type:    "bundle",
		ID:      newID("bundle", strings.Join(names, ",")),
		Objects: objects,
	}
}

func newID(typ, name string) string {
	return typ + "--" + uuidV5(nsKagemusha, typ+":"+name)
}

func uuidV5(ns [16]byte, name string) string {
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	s := h.Sum(nil)
	s[6] = (s[6] & 0x0F) | 0x50
	s[8] = (s[8] & 0x3F) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", s[0:4], s[4:6], s[6:8], s[8:10], s[10:16])
}

// Pattern returns the STIX 2.1 indicator pattern for an IOC.
func Pattern(typ model.IOCType, value string) string {
	switch typ {
	case model.TypeIPv4:
		return fmt.Sprintf("[ipv4-addr:value = '%s']", value)
	case model.TypeIPv6:
		return fmt.Sprintf("[ipv6-addr:value = '%s']", value)
	case model.TypeDomain:
		return fmt.Sprintf("[domain-name:value = '%s']", value)
	case model.TypeURL:
		return fmt.Sprintf("[url:value = '%s']", value)
	case model.TypeHashMD5:
		return fmt.Sprintf("[file:hashes.MD5 = '%s']", value)
	case model.TypeHashSHA1:
		return fmt.Sprintf("[file:hashes.'SHA-1' = '%s']", value)
	case model.TypeHashSHA256:
		return fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", value)
	default:
		return fmt.Sprintf("[artifact:payload_bin = '%s']", value)
	}
}

func indicatorTypes(v model.Verdict) []string {
	switch v {
	case model.Malicious:
		return []string{"malicious-activity"}
	case model.Suspicious:
		return []string{"anomalous-activity"}
	case model.Benign:
		return []string{"benign"}
	default:
		return []string{"unknown"}
	}
}

func description(r model.Result) string {
	parts := []string{fmt.Sprintf("Verdict: %s (%d%% confidence)", r.Verdict, r.Confidence)}
	for _, reason := range r.Reasons {
		parts = append(parts, reason.Message)
	}
	return strings.Join(parts, ". ") + "."
}

func externalRefs(r model.Result) []ExternalReference {
	var refs []ExternalReference
	for _, src := range r.Sources {
		if src.Reference == "" {
			continue
		}
		desc := src.Name
		if src.FirstSeen != "" {
			desc += " (first seen: " + src.FirstSeen + ")"
		}
		refs = append(refs, ExternalReference{
			SourceName:  src.Name,
			URL:         src.Reference,
			Description: desc,
		})
	}
	return refs
}

// abuseCHSources are the curated sources whose family labels are
// reliable enough for STIX Malware objects. OTX family names come
// from crowd-sourced pulses and can be arbitrary or wrong.
var abuseCHSources = map[string]bool{
	model.SourceURLhaus:   true,
	model.SourceThreatFox: true,
	model.SourceFeodo:     true,
}

func families(r model.Result) []string {
	seen := make(map[string]bool)
	var out []string
	for _, src := range r.Sources {
		if src.Status != model.StatusOk {
			continue
		}
		if !abuseCHSources[src.Name] {
			continue
		}
		if !strings.HasPrefix(src.Detail, "malware family: ") {
			continue
		}
		family := strings.TrimPrefix(src.Detail, "malware family: ")
		// Detail is "malware family: X | extra | extra" (secondary families,
		// Feodo port/status/staleness notes). Only X is the family.
		if i := strings.Index(family, " | "); i >= 0 {
			family = family[:i]
		}
		family = strings.TrimSpace(family)
		if family == "" {
			continue
		}
		if !seen[family] {
			seen[family] = true
			out = append(out, family)
		}
	}
	return out
}
