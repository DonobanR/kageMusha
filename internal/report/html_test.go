package report

import (
	"strings"
	"testing"
	"time"

	"github.com/DonobanR/kagemusha/internal/model"
)

func TestToHTML(t *testing.T) {
	results := []model.Result{
		{
			Target:     "192.168.1.1",
			Type:       model.TypeIPv4,
			Verdict:    model.Malicious,
			Confidence: 75,
			Reasons: []model.Reason{
				{Code: "threatfox_listed", Message: "Listed in threatfox (family: Cobalt Strike)"},
				{Code: "feodo_listed", Message: "Listed in feodo (family: Emotet)"},
			},
			Sources: []model.SourceResult{
				{
					Name:      "threatfox",
					Status:    model.StatusOk,
					Detail:    "malware family: Cobalt Strike",
					Reference: "https://threatfox.abuse.ch/ioc/12345",
					FirstSeen: "2024-01-15T10:30:00Z",
				},
				{
					Name:      "feodo",
					Status:    model.StatusOk,
					Detail:    "malware family: Emotet | C2 port 8080, status offline",
					Reference: "https://feodotracker.abuse.ch/browse/host/192.168.1.1/",
					FirstSeen: "2023-06-04T21:24:53Z",
				},
			},
		},
	}

	now := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	html, err := ToHTML(results, now)
	if err != nil {
		t.Fatalf("ToHTML() error: %v", err)
	}

	s := string(html)

	if !strings.Contains(s, "192.168.1.1") {
		t.Error("HTML does not contain the IOC IP address")
	}

	if !strings.Contains(s, "relationship") {
		t.Error("HTML does not contain a relationship (no arrows in graph)")
	}

	if !strings.Contains(s, "<!DOCTYPE html>") {
		t.Error("missing DOCTYPE")
	}

	if !strings.Contains(s, "marker") {
		t.Error("missing SVG arrow marker definition")
	}

	if !strings.Contains(s, "Cobalt Strike") {
		t.Error("missing malware family name")
	}

	if !strings.Contains(s, "malicious-activity") {
		t.Error("missing indicator type for malicious verdict")
	}

	if !strings.Contains(s, "threatfox.abuse.ch") {
		t.Error("missing external reference URL")
	}

	if len(html) > 20*1024 {
		t.Errorf("HTML size %d bytes exceeds 20KB limit", len(html))
	}

	if !strings.Contains(s, "#12121f") {
		t.Error("missing navy background color from palette")
	}
	if !strings.Contains(s, "#1a1a2e") {
		t.Error("missing charcoal panel color from palette")
	}
	if !strings.Contains(s, "showPanel") {
		t.Error("missing side panel function")
	}
	if !strings.Contains(s, "KAGEMUSHA") {
		t.Error("missing top bar branding")
	}
}

func TestToHTMLNoMalware(t *testing.T) {
	results := []model.Result{
		{
			Target:     "8.8.8.8",
			Type:       model.TypeIPv4,
			Verdict:    model.Unknown,
			Confidence: 0,
			Reasons: []model.Reason{
				{Code: "urlhaus_not_listed", Message: "Not listed in urlhaus"},
			},
			Sources: []model.SourceResult{
				{Name: "urlhaus", Status: model.StatusNotListed},
			},
		},
	}

	now := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	html, err := ToHTML(results, now)
	if err != nil {
		t.Fatalf("ToHTML() error: %v", err)
	}

	s := string(html)
	if !strings.Contains(s, "8.8.8.8") {
		t.Error("HTML does not contain the IOC IP address")
	}
	if !strings.Contains(s, "indicator") {
		t.Error("HTML does not contain an indicator node")
	}
}
