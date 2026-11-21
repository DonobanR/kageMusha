package report

import (
	"os"
	"os/exec"
	"path/filepath"
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

// Regression: color was derived from confidence alone, so a benign IOC at
// 95% was drawn red/"critical" and a one-anchor malicious (60%) yellow,
// indistinguishable from a 35% suspicious. Color is now by verdict and
// confidence only drives opacity.
func TestToHTMLColorByVerdict(t *testing.T) {
	out, err := ToHTML([]model.Result{{Target: "8.8.8.8", Type: model.TypeIPv4, Verdict: model.Benign, Confidence: 95}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h := string(out)
	for _, want := range []string{
		`if(v==="malicious")return{f:"#b03040"`,
		`if(v==="suspicious")return{f:"#c4722a"`,
		`if(v==="benign")return{f:"#2a6a8a"`,
		`if(v==="malicious-activity")return"malicious"`,
		`if(v==="anomalous-activity")return"suspicious"`,
		`>Malicious</span>`, `>Suspicious</span>`, `>Benign</span>`,
	} {
		if !strings.Contains(h, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	if strings.Contains(h, `"#8a7a2a"`) {
		t.Error("old confidence-based yellow still present")
	}
}

// The embedded JS is a Go string nobody compiles: a stray quote silently
// produced an empty graph (round 26). When node is installed, syntax-check it.
func TestToHTMLScriptSyntax(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	out, err := ToHTML([]model.Result{{Target: "1.2.3.4", Type: model.TypeIPv4, Verdict: model.Malicious, Confidence: 60}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h := string(out)
	i := strings.Index(h, "<script>")
	j := strings.LastIndex(h, "</script>")
	if i < 0 || j < 0 {
		t.Fatal("no <script> block")
	}
	f := filepath.Join(t.TempDir(), "graph.js")
	if err := os.WriteFile(f, []byte(h[i+len("<script>"):j]), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, err := exec.Command(node, "--check", f).CombinedOutput(); err != nil {
		t.Errorf("node --check failed: %v\n%s", err, b)
	}
}
