package cli

import (
	"context"

	"github.com/DonobanR/kagemusha/internal/model"
)

// DetermineExitCode maps scan outcome to process exit code.
//
//	0 — at least one IOC processed (any verdict)
//	1 — usage error (no IOCs, all invalid) — handled by caller before this
//	3 — all sources failed for all emitted IOCs
//	4 — timeout occurred (partial or total), overrides 3
func DetermineExitCode(ctx context.Context, results []model.Result) int {
	if ctx.Err() == context.DeadlineExceeded {
		return 4
	}

	if len(results) == 0 {
		return 1
	}

	if allSourcesFailed(results) {
		return 3
	}

	return 0
}

func allSourcesFailed(results []model.Result) bool {
	sawFailure := false
	for _, r := range results {
		if len(r.Sources) == 0 {
			// Processed but no applicable sources: not a failure.
			continue
		}
		for _, s := range r.Sources {
			switch s.Status {
			case model.StatusError, model.StatusTimeout, model.StatusRateLimited:
				sawFailure = true
			default:
				return false
			}
		}
	}
	return sawFailure
}
