package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/DonobanR/kagemusha/internal/cli"
	"github.com/DonobanR/kagemusha/internal/config"
	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/ratelimit"
	"github.com/DonobanR/kagemusha/internal/sources"
	"github.com/DonobanR/kagemusha/internal/report"
	"github.com/DonobanR/kagemusha/internal/sources/cdn"
	"github.com/DonobanR/kagemusha/internal/sources/feodo"
	"github.com/DonobanR/kagemusha/internal/sources/otx"
	"github.com/DonobanR/kagemusha/internal/sources/threatfox"
	"github.com/DonobanR/kagemusha/internal/sources/tranco"
	"github.com/DonobanR/kagemusha/internal/sources/urlhaus"
	"github.com/DonobanR/kagemusha/internal/stix"
)

func main() {
	var (
		abuseKey    = flag.String("abusech-auth-key", "", "abuse.ch Auth-Key (overrides env/config)")
		otxKey      = flag.String("otx-api-key", "", "AlienVault OTX API key (overrides env/config)")
		outFile     = flag.String("out", "", "write output to file instead of stdout")
		timeout     = flag.Duration("timeout", 0, "abort scan after duration (e.g. 30s, 2m); 0 = no timeout")
		workers     = flag.Int("workers", 10, "max concurrent IOCs (default 10)")
		stixOutput  = flag.Bool("stix", false, "STIX 2.1 bundle output")
		htmlOutput  = flag.Bool("html", false, "self-contained HTML graph report")
		jsonOutput  = flag.Bool("json", false, "JSON output (default)")
		verbose     = flag.Bool("verbose", false, "print debug info to stderr")
		lowMemory   = flag.Bool("low-memory", false, "use linear scan instead of in-memory map for Tranco (~15 MB vs ~120 MB)")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: kagemusha scan [flags] <ioc> [<ioc>...]\n\n")
		fmt.Fprintf(os.Stderr, "Triage IOCs against threat intelligence feeds.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	reorderArgs()
	flag.Parse()

	if *showVersion {
		fmt.Println("kagemusha v0.1.0-dev")
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "error: no IOCs provided")
		flag.Usage()
		os.Exit(1)
	}

	// Strip "scan" subcommand if present.
	if args[0] == "scan" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "error: no IOCs provided after 'scan'")
		os.Exit(1)
	}

	cfg, warnings, err := config.Load(config.Flags{
		AbuseCHAuthKey: *abuseKey,
		OTXAPIKey:      *otxKey,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(2)
	}
	for _, w := range warnings {
		fmt.Fprintln(os.Stderr, w)
	}

	// Always warn (not just with --verbose): without the key every IOC would
	// otherwise come out "partial" with no explanation.
	if cfg.AbuseCHAuthKey == "" {
		fmt.Fprintln(os.Stderr, "warning: missing abuse.ch auth key: URLhaus and ThreatFox will not respond (set KAGEMUSHA_ABUSECH_AUTH_KEY, config.yaml or --abusech-auth-key; free key at https://auth.abuse.ch/)")
	}

	if *verbose {
		if cfg.AbuseCHAuthKey != "" {
			fmt.Fprintf(os.Stderr, "abuse.ch auth key: %s\n", config.MaskKey(cfg.AbuseCHAuthKey))
		}
		if cfg.OTXAPIKey != "" {
			fmt.Fprintf(os.Stderr, "OTX API key: %s\n", config.MaskKey(cfg.OTXAPIKey))
		} else {
			fmt.Fprintln(os.Stderr, "warning: no OTX API key configured; OTX queries will use anonymous rate limits")
		}
	}

	ctx := context.Background()
	if *timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}

	threatSrcs := []sources.ThreatSource{
		urlhaus.New(cfg.AbuseCHAuthKey),
		threatfox.New(cfg.AbuseCHAuthKey),
	}
	feodoClient, err := feodo.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: feodo unavailable: %v\n", err)
	} else {
		threatSrcs = append(threatSrcs, feodoClient)
	}

	threatSrcs = append(threatSrcs, otx.New(cfg.OTXAPIKey))

	var fpSrcs []sources.FPSource
	trancoClient, err := tranco.New(*lowMemory)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: tranco unavailable: %v\n", err)
	} else {
		fpSrcs = append(fpSrcs, trancoClient)
	}

	var enrichSrcs []sources.EnrichmentSource
	cdnClient, err := cdn.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cdn unavailable: %v\n", err)
	} else {
		enrichSrcs = append(enrichSrcs, cdnClient)
	}

	// Pool A: abuse.ch API sources share a 1 req/s rate limiter.
	// Pool B: OTX gets its own 2 req/s limiter.
	poolA := ratelimit.New(time.Second)
	defer poolA.Close()
	poolB := ratelimit.New(500 * time.Millisecond)
	defer poolB.Close()

	results, err := cli.RunScan(ctx, cli.ScanOptions{
		RawIOCs:           args,
		ThreatSources:     threatSrcs,
		FPSources:         fpSrcs,
		EnrichmentSources: enrichSrcs,
		Limiters: map[string]*ratelimit.Bucket{
			model.SourceURLhaus:   poolA,
			model.SourceThreatFox: poolA,
			model.SourceOTX:       poolB,
		},
		Workers: *workers,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	formats := 0
	if *stixOutput {
		formats++
	}
	if *htmlOutput {
		formats++
	}
	if *jsonOutput {
		formats++
	}
	if formats > 1 {
		fmt.Fprintln(os.Stderr, "error: --stix, --html, and --json are mutually exclusive")
		os.Exit(1)
	}

	exitCode := cli.DetermineExitCode(ctx, results)

	now := time.Now().UTC()
	var data []byte

	if *htmlOutput {
		data, err = report.ToHTML(results, now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error generating HTML report: %v\n", err)
			os.Exit(1)
		}
	} else {
		var output any
		if *stixOutput {
			actionable, skipped := stix.FilterActionable(results)
			if skipped > 0 {
				fmt.Fprintf(os.Stderr, "%d result(s) omitted from STIX bundle (benign/unknown, or threat on shared domain — investigate at URL level)\n", skipped)
			}
			output = stix.ToBundle(actionable, now)
		} else {
			output = results
		}
		data, err = json.MarshalIndent(output, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error marshaling results: %v\n", err)
			os.Exit(1)
		}
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *outFile, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Results written to %s\n", *outFile)
		if *htmlOutput {
			openInBrowser(*outFile)
		}
	} else {
		fmt.Println(string(data))
	}

	os.Exit(exitCode)
}

func openInBrowser(path string) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return
	}
	switch runtime.GOOS {
	case "windows":
		exec.Command("cmd", "/c", "start", "", abs).Start()
	case "darwin":
		exec.Command("open", abs).Start()
	default:
		exec.Command("xdg-open", abs).Start()
	}
}

func reorderArgs() {
	raw := os.Args[1:]
	var flags, positional []string

	for i := 0; i < len(raw); i++ {
		a := raw[i]
		if !strings.HasPrefix(a, "-") {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		if strings.Contains(a, "=") {
			continue
		}
		name := strings.TrimLeft(a, "-")
		f := flag.CommandLine.Lookup(name)
		if f == nil {
			continue
		}
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			continue
		}
		if i+1 < len(raw) {
			i++
			flags = append(flags, raw[i])
		}
	}

	os.Args = append([]string{os.Args[0]}, append(flags, positional...)...)
}
