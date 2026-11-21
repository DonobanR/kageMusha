package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/ratelimit"
	"github.com/DonobanR/kagemusha/internal/scoring"
	"github.com/DonobanR/kagemusha/internal/sources"
	"github.com/DonobanR/kagemusha/internal/wellknown"
)

// ScanOptions holds the inputs for a scan.
type ScanOptions struct {
	RawIOCs           []string
	ThreatSources     []sources.ThreatSource
	FPSources         []sources.FPSource
	EnrichmentSources []sources.EnrichmentSource
	Limiters          map[string]*ratelimit.Bucket // per-source rate limiters (nil map or missing key = no limit)
	Workers           int                          // max concurrent IOCs (default 10)
	Now               time.Time                    // zero means time.Now() — inject for deterministic tests
}

// RunScan is the core scan loop: parse → fan-out → score → collect.
// IOCs are processed concurrently up to Workers; results preserve
// input order. Pool A sources (abuse.ch) are serialized through
// Limiter; Pool B sources run unconstrained.
func RunScan(ctx context.Context, opts ScanOptions) ([]model.Result, error) {
	var iocs []model.IOC
	var wellknownResults []model.Result
	for _, raw := range opts.RawIOCs {
		if ctx.Err() != nil {
			break
		}
		ioc, err := ParseIOC(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping %q: %v\n", raw, err)
			continue
		}
		if ioc.Type == model.TypeIPv4 || ioc.Type == model.TypeIPv6 {
			if label, kind := wellknown.Check(ioc.Value); kind != wellknown.KindNone {
				var r model.Result
				switch kind {
				case wellknown.KindInfra:
					r = model.Result{
						Target: ioc.Value, Type: ioc.Type,
						Verdict: model.Benign, Confidence: 95,
						Reasons: []model.Reason{{Code: "wellknown", Message: label}},
					}
				case wellknown.KindNotRoutable:
					r = model.Result{
						Target: ioc.Value, Type: ioc.Type,
						Verdict: model.Unknown, Confidence: 0,
						Reasons: []model.Reason{{Code: "not_routable", Message: label + ": outside scope of external threat intelligence"}},
					}
				}
				wellknownResults = append(wellknownResults, r)
				continue
			}
		}
		iocs = append(iocs, ioc)
	}
	if len(iocs) == 0 && len(wellknownResults) == 0 {
		return nil, fmt.Errorf("no IOCs processed successfully")
	}
	if len(iocs) == 0 {
		return wellknownResults, nil
	}

	workers := opts.Workers
	if workers <= 0 {
		workers = 10
	}
	if workers > len(iocs) {
		workers = len(iocs)
	}

	results := make([]model.Result, len(iocs))
	errs := make([]error, len(iocs))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for i, ioc := range iocs {
		if ctx.Err() != nil {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(idx int, ioc model.IOC) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx], errs[idx] = scanOne(ctx, ioc, opts)
		}(i, ioc)
	}
	wg.Wait()

	var out []model.Result
	for i := range iocs {
		if errs[i] != nil {
			return nil, errs[i]
		}
		if results[i].Target != "" {
			out = append(out, results[i])
		}
	}
	out = append(wellknownResults, out...)
	if len(out) == 0 {
		return nil, fmt.Errorf("no IOCs processed successfully")
	}
	return out, nil
}

func scanOne(ctx context.Context, ioc model.IOC, opts ScanOptions) (model.Result, error) {
	// Filter applicable sources.
	var appThreats []sources.ThreatSource
	var appFPs []sources.FPSource
	var appEnrich []sources.EnrichmentSource

	for _, s := range opts.ThreatSources {
		if s.AppliesTo(ioc.Type) {
			appThreats = append(appThreats, s)
		}
	}
	for _, s := range opts.FPSources {
		if s.AppliesTo(ioc.Type) {
			appFPs = append(appFPs, s)
		}
	}
	for _, s := range opts.EnrichmentSources {
		if s.AppliesTo(ioc.Type) {
			appEnrich = append(appEnrich, s)
		}
	}

	// Pre-allocate indexed slices for deterministic output order.
	threatEvs := make([]sources.ThreatEvidence, len(appThreats))
	threatErrs := make([]error, len(appThreats))
	fpEvs := make([]sources.FPEvidence, len(appFPs))
	fpErrs := make([]error, len(appFPs))
	enrichLines := make([][]string, len(appEnrich))

	var wg sync.WaitGroup

	// Fan out threat sources (rate-limited sources wait for their bucket).
	for i, s := range appThreats {
		wg.Add(1)
		go func(idx int, src sources.ThreatSource) {
			defer wg.Done()
			if lim := opts.Limiters[src.Name()]; lim != nil {
				if err := lim.Wait(ctx); err != nil {
					threatEvs[idx] = sources.ThreatEvidence{
						Source: src.Name(),
						Status: model.StatusTimeout,
					}
					return
				}
			}
			threatEvs[idx], threatErrs[idx] = src.Lookup(ctx, ioc)
		}(i, s)
	}

	// Fan out FP sources (always Pool B).
	for i, s := range appFPs {
		wg.Add(1)
		go func(idx int, src sources.FPSource) {
			defer wg.Done()
			fpEvs[idx], fpErrs[idx] = src.Check(ctx, ioc)
		}(i, s)
	}

	// Fan out enrichment sources (always Pool B).
	for i, s := range appEnrich {
		wg.Add(1)
		go func(idx int, src sources.EnrichmentSource) {
			defer wg.Done()
			lines, err := src.Enrich(ctx, ioc)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: enrichment %s failed: %v\n", src.Name(), err)
				return
			}
			enrichLines[idx] = lines
		}(i, s)
	}

	wg.Wait()

	// Check for programmer bugs (non-nil errors violate the source contract).
	for i, err := range threatErrs {
		if err != nil {
			return model.Result{}, fmt.Errorf("BUG: %s returned error: %w", appThreats[i].Name(), err)
		}
	}
	for i, err := range fpErrs {
		if err != nil {
			return model.Result{}, fmt.Errorf("BUG: %s returned error: %w", appFPs[i].Name(), err)
		}
	}

	// Build result — sources in input order.
	var allSources []model.SourceResult
	var reasons []model.Reason
	for _, ev := range threatEvs {
		allSources = append(allSources, model.SourceResult{
			Name:      ev.Source,
			Status:    ev.Status,
			Detail:    threatDetail(ev),
			Reference: ev.Reference,
			FirstSeen: ev.FirstSeen,
			LastSeen:  ev.LastSeen,
		})
		reasons = append(reasons, threatReason(ev)...)
	}
	for _, ev := range fpEvs {
		allSources = append(allSources, model.SourceResult{
			Name:   ev.Source,
			Status: ev.Status,
			Detail: fpDetail(ev),
		})
		reasons = append(reasons, fpReason(ev)...)
	}

	var contextLines []string
	for _, lines := range enrichLines {
		contextLines = append(contextLines, lines...)
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	decay := scoring.DecayFactors(ioc.Type, threatEvs, now)
	if decay != nil {
		for _, ev := range threatEvs {
			if ev.Status != model.StatusOk {
				continue
			}
			dateStr := ev.LastSeen
			if dateStr == "" {
				dateStr = ev.FirstSeen
			}
			if dateStr != "" {
				if _, ok := decay[ev.Source]; !ok {
					fmt.Fprintf(os.Stderr, "warning: %s date %q could not be parsed for decay\n", ev.Source, dateStr)
				}
			}
		}
	}
	threat := scoring.ThreatScore(threatEvs, decay)
	fp := scoring.FPScore(fpEvs)
	var failedSources []string
	for _, ev := range threatEvs {
		switch ev.Status {
		case model.StatusError, model.StatusTimeout, model.StatusRateLimited:
			failedSources = append(failedSources, ev.Source)
		}
	}

	verdict := scoring.Decide(threat.Score, fp.Score, threat.HasAnchor, threat.HasFreshAnchor)
	// "Benign" means popular AND nobody flags it. If an applicable threat
	// source failed we cannot know the second half, so a verdict that would
	// be benign becomes unknown (partial stays set, failed sources listed).
	if verdict == model.Benign && len(failedSources) > 0 {
		verdict = model.Unknown
		reasons = append(reasons, model.Reason{
			Code:    "incomplete",
			Message: fmt.Sprintf("Incomplete: threat sources failed (%s); cannot conclude benign", strings.Join(failedSources, ", ")),
		})
	}
	confidence := scoring.Calculate(verdict, threat, fp)

	historical := verdict == model.Suspicious &&
		threat.HasAnchor &&
		threat.Score < scoring.ThreatSuspiciousThreshold
	if historical {
		reasons = append(reasons, model.Reason{
			Code:    "historical",
			Message: "Anchor source listed this IOC historically; verdict held at suspicious due to age decay",
		})
	}

	return model.Result{
		Target:        ioc.Value,
		Type:          ioc.Type,
		Verdict:       verdict,
		Confidence:    confidence,
		FPScore:       fp.Score,
		Partial:       len(failedSources) > 0,
		Historical:    historical,
		FailedSources: failedSources,
		Context:       contextLines,
		Reasons:       reasons,
		Sources:       allSources,
	}, nil
}

func threatDetail(ev sources.ThreatEvidence) string {
	if ev.Status == model.StatusSuppressed && ev.Extra != "" {
		return ev.Extra
	}
	if ev.Status != model.StatusOk || ev.MalwareFamily == "" {
		return ""
	}
	detail := fmt.Sprintf("malware family: %s", ev.MalwareFamily)
	if ev.Extra != "" {
		detail += " | " + ev.Extra
	}
	return detail
}

func threatReason(ev sources.ThreatEvidence) []model.Reason {
	switch ev.Status {
	case model.StatusOk:
		var msg string
		switch {
		case ev.MalwareFamily != "":
			msg = fmt.Sprintf("Listed in %s (family: %s)", ev.Source, ev.MalwareFamily)
		case ev.Extra != "":
			msg = fmt.Sprintf("Listed in %s (%s)", ev.Source, ev.Extra)
		default:
			msg = fmt.Sprintf("Listed in %s", ev.Source)
		}
		return []model.Reason{{Code: ev.Source + "_listed", Message: msg}}
	case model.StatusNotListed:
		return []model.Reason{{
			Code:    ev.Source + "_not_listed",
			Message: fmt.Sprintf("Not listed in %s", ev.Source),
		}}
	case model.StatusSuppressed:
		msg := fmt.Sprintf("%s data suppressed", ev.Source)
		if ev.Extra != "" {
			msg = fmt.Sprintf("%s suppressed: %s", ev.Source, ev.Extra)
		}
		return []model.Reason{{
			Code:    ev.Source + "_suppressed",
			Message: msg,
		}}
	case model.StatusTimeout:
		msg := fmt.Sprintf("%s request timed out", ev.Source)
		if ev.Extra != "" {
			msg = fmt.Sprintf("%s: %s", ev.Source, ev.Extra)
		}
		return []model.Reason{{Code: ev.Source + "_timeout", Message: msg}}
	case model.StatusRateLimited:
		msg := fmt.Sprintf("%s rate limited", ev.Source)
		if ev.Extra != "" {
			msg = fmt.Sprintf("%s: %s", ev.Source, ev.Extra)
		}
		return []model.Reason{{Code: ev.Source + "_rate_limited", Message: msg}}
	case model.StatusError:
		msg := fmt.Sprintf("%s request failed", ev.Source)
		if ev.Extra != "" {
			msg = fmt.Sprintf("%s: %s", ev.Source, ev.Extra)
		}
		return []model.Reason{{Code: ev.Source + "_error", Message: msg}}
	default:
		return nil
	}
}

func fpDetail(ev sources.FPEvidence) string {
	if ev.Status != model.StatusOk || len(ev.Signals) == 0 {
		return ""
	}
	names := make([]string, len(ev.Signals))
	for i, s := range ev.Signals {
		names[i] = string(s)
	}
	return fmt.Sprintf("signals: %s", strings.Join(names, ", "))
}

func fpReason(ev sources.FPEvidence) []model.Reason {
	if ev.Status != model.StatusOk {
		return nil
	}
	if len(ev.Signals) == 0 {
		return []model.Reason{{
			Code:    ev.Source + "_clean",
			Message: fmt.Sprintf("Not found in %s", ev.Source),
		}}
	}
	return []model.Reason{{
		Code:    ev.Source + "_found",
		Message: fmt.Sprintf("Found in %s (%d benign signals)", ev.Source, len(ev.Signals)),
	}}
}
