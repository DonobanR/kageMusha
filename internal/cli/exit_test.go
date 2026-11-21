package cli_test

import (
	"context"
	"testing"
	"time"

	"github.com/DonobanR/kagemusha/internal/cli"
	"github.com/DonobanR/kagemusha/internal/model"
)

func TestDetermineExitCodeSuccess(t *testing.T) {
	results := []model.Result{
		{
			Target: "evil.com",
			Sources: []model.SourceResult{
				{Name: "urlhaus", Status: model.StatusOk},
			},
		},
	}
	code := cli.DetermineExitCode(context.Background(), results)
	if code != 0 {
		t.Errorf("got %d, want 0", code)
	}
}

func TestDetermineExitCodeNotListedIsSuccess(t *testing.T) {
	results := []model.Result{
		{
			Target: "google.com",
			Sources: []model.SourceResult{
				{Name: "urlhaus", Status: model.StatusNotListed},
			},
		},
	}
	code := cli.DetermineExitCode(context.Background(), results)
	if code != 0 {
		t.Errorf("got %d, want 0 (not_listed is a successful response)", code)
	}
}

func TestDetermineExitCodeAllSourcesFailed(t *testing.T) {
	results := []model.Result{
		{
			Target: "evil.com",
			Sources: []model.SourceResult{
				{Name: "urlhaus", Status: model.StatusError},
			},
		},
		{
			Target: "bad.com",
			Sources: []model.SourceResult{
				{Name: "urlhaus", Status: model.StatusRateLimited},
			},
		},
	}
	code := cli.DetermineExitCode(context.Background(), results)
	if code != 3 {
		t.Errorf("got %d, want 3", code)
	}
}

func TestDetermineExitCodeTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond) // ensure deadline passed

	results := []model.Result{
		{
			Target: "evil.com",
			Sources: []model.SourceResult{
				{Name: "urlhaus", Status: model.StatusOk},
			},
		},
	}
	code := cli.DetermineExitCode(ctx, results)
	if code != 4 {
		t.Errorf("got %d, want 4", code)
	}
}

func TestDetermineExitCodeTimeoutOverridesAllFailed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond)

	results := []model.Result{
		{
			Target: "evil.com",
			Sources: []model.SourceResult{
				{Name: "urlhaus", Status: model.StatusError},
			},
		},
	}
	code := cli.DetermineExitCode(ctx, results)
	if code != 4 {
		t.Errorf("got %d, want 4 (timeout overrides all-failed)", code)
	}
}

func TestDetermineExitCodeMixedSuccessFailure(t *testing.T) {
	results := []model.Result{
		{
			Target: "evil.com",
			Sources: []model.SourceResult{
				{Name: "urlhaus", Status: model.StatusError},
			},
		},
		{
			Target: "google.com",
			Sources: []model.SourceResult{
				{Name: "urlhaus", Status: model.StatusOk},
			},
		},
	}
	code := cli.DetermineExitCode(context.Background(), results)
	if code != 0 {
		t.Errorf("got %d, want 0 (one IOC succeeded)", code)
	}
}

func TestDetermineExitCodeMixedWithinIOC(t *testing.T) {
	results := []model.Result{
		{
			Target: "evil.com",
			Sources: []model.SourceResult{
				{Name: "urlhaus", Status: model.StatusError},
				{Name: "tranco", Status: model.StatusNotListed},
			},
		},
	}
	code := cli.DetermineExitCode(context.Background(), results)
	if code != 0 {
		t.Errorf("got %d, want 0 (not_listed within same IOC counts as success)", code)
	}
}

func TestDetermineExitCodeNoSourcesIsNotFailure(t *testing.T) {
	results := []model.Result{
		{Target: "something.test", Sources: []model.SourceResult{}},
	}
	code := cli.DetermineExitCode(context.Background(), results)
	if code != 0 {
		t.Errorf("got %d, want 0 (no sources applied is not a failure)", code)
	}
}
