package stix

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/DonobanR/kagemusha/internal/model"
)

var fixedTime = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func TestBundleWithMalware(t *testing.T) {
	results := []model.Result{{
		Target:     "162.243.103.246",
		Type:       model.TypeIPv4,
		Verdict:    model.Malicious,
		Confidence: 66,
		Reasons: []model.Reason{
			{Code: "threatfox_listed", Message: "Listed in threatfox (family: Cobalt Strike)"},
			{Code: "feodo_listed", Message: "Listed in feodo (family: Emotet)"},
		},
		Sources: []model.SourceResult{
			{Name: "threatfox", Status: model.StatusOk, Detail: "malware family: Cobalt Strike"},
			{Name: "feodo", Status: model.StatusOk, Detail: "malware family: Emotet"},
			{Name: "urlhaus", Status: model.StatusNotListed},
		},
	}}

	b := ToBundle(results, fixedTime)

	if b.Type != "bundle" {
		t.Errorf("bundle type = %q, want bundle", b.Type)
	}
	if !strings.HasPrefix(b.ID, "bundle--") {
		t.Errorf("bundle ID = %q, want bundle-- prefix", b.ID)
	}

	// 1 Indicator + 2 Malware + 2 Relationship = 5 objects.
	if len(b.Objects) != 5 {
		t.Fatalf("objects = %d, want 5", len(b.Objects))
	}

	ind := b.Objects[0].(Indicator)
	if ind.Type != "indicator" {
		t.Errorf("type = %q", ind.Type)
	}
	if ind.SpecVersion != "2.1" {
		t.Errorf("spec_version = %q", ind.SpecVersion)
	}
	if ind.Pattern != "[ipv4-addr:value = '162.243.103.246']" {
		t.Errorf("pattern = %q", ind.Pattern)
	}
	if ind.IndicatorTypes[0] != "malicious-activity" {
		t.Errorf("indicator_types = %v", ind.IndicatorTypes)
	}
	if ind.Confidence != 66 {
		t.Errorf("confidence = %d", ind.Confidence)
	}

	mal1 := b.Objects[1].(Malware)
	if mal1.Name != "Cobalt Strike" {
		t.Errorf("malware[0] name = %q", mal1.Name)
	}
	if !mal1.IsFamily {
		t.Error("is_family should be true")
	}

	rel1 := b.Objects[2].(Relationship)
	if rel1.RelationshipType != "indicates" {
		t.Errorf("relationship_type = %q", rel1.RelationshipType)
	}
	if rel1.SourceRef != ind.ID {
		t.Errorf("source_ref = %q, want %q", rel1.SourceRef, ind.ID)
	}
	if rel1.TargetRef != mal1.ID {
		t.Errorf("target_ref = %q, want %q", rel1.TargetRef, mal1.ID)
	}

	mal2 := b.Objects[3].(Malware)
	if mal2.Name != "Emotet" {
		t.Errorf("malware[1] name = %q", mal2.Name)
	}
}

func TestFilterActionable(t *testing.T) {
	results := []model.Result{
		{Target: "evil.com", Verdict: model.Malicious},
		{Target: "google.com", Verdict: model.Benign},
		{Target: "sketchy.com", Verdict: model.Suspicious, FPScore: 0},
		{Target: "random.test", Verdict: model.Unknown},
		{Target: "github.com", Verdict: model.Suspicious, FPScore: 60},
		{Target: "old-c2.com", Verdict: model.Suspicious, FPScore: 0, Historical: true},
	}

	actionable, skipped := FilterActionable(results)
	if skipped != 4 {
		t.Errorf("skipped = %d, want 4 (benign + unknown + suspicious-high-FP + historical)", skipped)
	}
	if len(actionable) != 2 {
		t.Fatalf("actionable = %d, want 2", len(actionable))
	}
	if actionable[0].Target != "evil.com" {
		t.Errorf("actionable[0] = %q, want evil.com", actionable[0].Target)
	}
	if actionable[1].Target != "sketchy.com" {
		t.Errorf("actionable[1] = %q, want sketchy.com (low FP suspicious passes)", actionable[1].Target)
	}
}

func TestFilterActionableSuspiciousHighFP(t *testing.T) {
	results := []model.Result{
		{Target: "github.com", Verdict: model.Suspicious, FPScore: 60, Confidence: 20},
	}

	actionable, skipped := FilterActionable(results)
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 (suspicious with FP >= veto threshold)", skipped)
	}
	if len(actionable) != 0 {
		t.Errorf("actionable = %d, want 0 (suspicious + high FP = likely false positive)", len(actionable))
	}
}

func TestBundleIncludesAllVerdicts(t *testing.T) {
	results := []model.Result{
		{Target: "google.com", Type: model.TypeDomain, Verdict: model.Benign, Confidence: 60},
		{Target: "random.test", Type: model.TypeDomain, Verdict: model.Unknown, Confidence: 0},
	}

	b := ToBundle(results, fixedTime)
	if len(b.Objects) != 2 {
		t.Fatalf("objects = %d, want 2 (ToBundle includes all verdicts)", len(b.Objects))
	}
}

func TestBundleSuspiciousIncluded(t *testing.T) {
	results := []model.Result{{
		Target:     "sketchy.com",
		Type:       model.TypeDomain,
		Verdict:    model.Suspicious,
		Confidence: 40,
		Sources:    []model.SourceResult{{Name: "urlhaus", Status: model.StatusOk, Detail: "malware family: Emotet"}},
	}}

	b := ToBundle(results, fixedTime)

	if len(b.Objects) == 0 {
		t.Fatal("suspicious results should be included in STIX bundle")
	}

	ind := b.Objects[0].(Indicator)
	if ind.IndicatorTypes[0] != "anomalous-activity" {
		t.Errorf("indicator_types = %v, want [anomalous-activity]", ind.IndicatorTypes)
	}
}

func TestMalwareDeduplication(t *testing.T) {
	results := []model.Result{
		{
			Target:  "1.1.1.1",
			Type:    model.TypeIPv4,
			Verdict: model.Malicious,
			Sources: []model.SourceResult{
				{Name: "threatfox", Status: model.StatusOk, Detail: "malware family: Cobalt Strike"},
			},
		},
		{
			Target:  "2.2.2.2",
			Type:    model.TypeIPv4,
			Verdict: model.Malicious,
			Sources: []model.SourceResult{
				{Name: "threatfox", Status: model.StatusOk, Detail: "malware family: Cobalt Strike"},
			},
		},
	}

	b := ToBundle(results, fixedTime)

	var malCount int
	for _, obj := range b.Objects {
		if _, ok := obj.(Malware); ok {
			malCount++
		}
	}
	if malCount != 1 {
		t.Errorf("Cobalt Strike malware objects = %d, want 1 (dedup)", malCount)
	}

	// 2 Indicators + 1 Malware + 2 Relationships = 5.
	if len(b.Objects) != 5 {
		t.Fatalf("objects = %d, want 5", len(b.Objects))
	}
}

func TestDeterministicIDs(t *testing.T) {
	results := []model.Result{{
		Target:  "evil.com",
		Type:    model.TypeDomain,
		Verdict: model.Malicious,
	}}

	b1 := ToBundle(results, fixedTime)
	b2 := ToBundle(results, fixedTime)

	if b1.ID != b2.ID {
		t.Error("bundle IDs should be deterministic")
	}
	ind1 := b1.Objects[0].(Indicator)
	ind2 := b2.Objects[0].(Indicator)
	if ind1.ID != ind2.ID {
		t.Error("indicator IDs should be deterministic")
	}
}

func TestPatternAllTypes(t *testing.T) {
	cases := []struct {
		typ  model.IOCType
		val  string
		want string
	}{
		{model.TypeIPv4, "1.2.3.4", "[ipv4-addr:value = '1.2.3.4']"},
		{model.TypeIPv6, "::1", "[ipv6-addr:value = '::1']"},
		{model.TypeDomain, "evil.com", "[domain-name:value = 'evil.com']"},
		{model.TypeURL, "http://evil.com/pay", "[url:value = 'http://evil.com/pay']"},
		{model.TypeHashMD5, "abc123", "[file:hashes.MD5 = 'abc123']"},
		{model.TypeHashSHA1, "def456", "[file:hashes.'SHA-1' = 'def456']"},
		{model.TypeHashSHA256, "ghi789", "[file:hashes.'SHA-256' = 'ghi789']"},
	}
	for _, tc := range cases {
		got := Pattern(tc.typ, tc.val)
		if got != tc.want {
			t.Errorf("Pattern(%s, %q) = %q, want %q", tc.typ, tc.val, got, tc.want)
		}
	}
}

func TestIndicatorTypeMapping(t *testing.T) {
	cases := []struct {
		verdict model.Verdict
		want    string
	}{
		{model.Malicious, "malicious-activity"},
		{model.Suspicious, "anomalous-activity"},
		{model.Benign, "benign"},
		{model.Unknown, "unknown"},
	}
	for _, tc := range cases {
		got := indicatorTypes(tc.verdict)
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("indicatorTypes(%q) = %v, want [%q]", tc.verdict, got, tc.want)
		}
	}
}

func TestBundleValidJSON(t *testing.T) {
	results := []model.Result{{
		Target:     "evil.com",
		Type:       model.TypeDomain,
		Verdict:    model.Malicious,
		Confidence: 60,
		Sources: []model.SourceResult{
			{Name: "urlhaus", Status: model.StatusOk, Detail: "malware family: Mozi"},
		},
	}}

	b := ToBundle(results, fixedTime)
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal("invalid JSON:", err)
	}
	if parsed["type"] != "bundle" {
		t.Errorf("type = %v", parsed["type"])
	}

	objects := parsed["objects"].([]any)
	// 1 Indicator + 1 Malware + 1 Relationship = 3.
	if len(objects) != 3 {
		t.Fatalf("objects = %d, want 3", len(objects))
	}

	ind := objects[0].(map[string]any)
	if ind["spec_version"] != "2.1" {
		t.Error("missing spec_version 2.1")
	}
	if ind["pattern_type"] != "stix" {
		t.Error("missing pattern_type stix")
	}

	s := string(data)
	if !strings.Contains(s, "\"relationship_type\": \"indicates\"") {
		t.Error("missing indicates relationship in JSON")
	}
}

func TestExternalReferences(t *testing.T) {
	results := []model.Result{{
		Target:     "1.2.3.4",
		Type:       model.TypeIPv4,
		Verdict:    model.Malicious,
		Confidence: 75,
		Sources: []model.SourceResult{
			{
				Name:      "threatfox",
				Status:    model.StatusOk,
				Detail:    "malware family: Emotet",
				Reference: "https://threatfox.abuse.ch/ioc/123456",
				FirstSeen: "2026-11-18T14:30:00Z",
			},
			{
				Name:      "feodo",
				Status:    model.StatusOk,
				Detail:    "malware family: Emotet",
				Reference: "https://feodotracker.abuse.ch/browse/host/1.2.3.4/",
				FirstSeen: "2026-11-19T08:00:00Z",
			},
			{Name: "urlhaus", Status: model.StatusNotListed},
		},
	}}

	b := ToBundle(results, fixedTime)
	ind := b.Objects[0].(Indicator)

	if len(ind.ExternalReferences) != 2 {
		t.Fatalf("external_references = %d, want 2", len(ind.ExternalReferences))
	}
	if ind.ExternalReferences[0].SourceName != "threatfox" {
		t.Errorf("ref[0].source_name = %q", ind.ExternalReferences[0].SourceName)
	}
	if ind.ExternalReferences[0].URL != "https://threatfox.abuse.ch/ioc/123456" {
		t.Errorf("ref[0].url = %q", ind.ExternalReferences[0].URL)
	}
	if !strings.Contains(ind.ExternalReferences[0].Description, "first seen:") {
		t.Errorf("ref[0].description = %q, want 'first seen:' in it", ind.ExternalReferences[0].Description)
	}
	if ind.ExternalReferences[1].SourceName != "feodo" {
		t.Errorf("ref[1].source_name = %q", ind.ExternalReferences[1].SourceName)
	}
}

func TestFamilyExtraction(t *testing.T) {
	r := model.Result{
		Sources: []model.SourceResult{
			{Name: "threatfox", Status: model.StatusOk, Detail: "malware family: Cobalt Strike"},
			{Name: "feodo", Status: model.StatusOk, Detail: "malware family: Cobalt Strike"},
			{Name: "urlhaus", Status: model.StatusNotListed},
			{Name: "tranco", Status: model.StatusOk, Detail: "signals: tranco_top_1m"},
		},
	}

	fam := families(r)
	if len(fam) != 1 {
		t.Fatalf("families = %v, want [Cobalt Strike]", fam)
	}
	if fam[0] != "Cobalt Strike" {
		t.Errorf("family = %q", fam[0])
	}
}

// Regression (round-21 acceptance run): Malware names came out as
// "Emotet | C2 port 8080, status offline | CSV is 261 days old" because the
// whole Detail string was used. Strings below are real Detail values.
func TestFamilyExtractionStripsExtraDetail(t *testing.T) {
	r := model.Result{
		Sources: []model.SourceResult{
			{Name: "threatfox", Status: model.StatusOk, Detail: "malware family: Cobalt Strike | also: Emotet"},
			{Name: "feodo", Status: model.StatusOk, Detail: "malware family: Emotet | C2 port 8080, status offline | CSV is 261 days old"},
		},
	}
	fam := families(r)
	want := []string{"Cobalt Strike", "Emotet"}
	if len(fam) != len(want) || fam[0] != want[0] || fam[1] != want[1] {
		t.Errorf("families = %q, want %q", fam, want)
	}
}

