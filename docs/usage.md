# Usage reference

Full reference for the flags, config locations and exit codes summarized in [README.md](../README.md).

## Configuration

Kagemusha reads config from (highest priority first):

1. CLI flags (`--abusech-auth-key`, `--otx-api-key`)
2. Environment variables (`KAGEMUSHA_ABUSECH_AUTH_KEY`, `KAGEMUSHA_OTX_API_KEY`)
3. Local `./config.yaml`
4. Global `%APPDATA%/kagemusha/config.yaml` (Windows) or `~/.config/kagemusha/config.yaml` (Linux/macOS)

```yaml
# config.yaml
abusech_auth_key: "your-key-here"
otx_api_key: "your-otx-key-here"
```

Note: only one config file is read, `./config.yaml` if it exists, otherwise the global one; they are not merged.

## Flags

```
--abusech-auth-key   abuse.ch Auth-Key (overrides env/config)
--otx-api-key        AlienVault OTX API key (overrides env/config)
--out FILE           write output to file instead of stdout
--stix               STIX 2.1 bundle output (only malicious/suspicious IOCs)
--html               interactive HTML graph report (use with --out FILE)
--json               JSON output (default)
--timeout DURATION   abort scan after duration (e.g. 30s, 2m)
--workers N          max concurrent IOCs (default 10)
--low-memory         linear scan for Tranco (~15 MB vs ~120 MB)
--verbose            print debug info to stderr
--version            print version and exit
```

`--stix`, `--html` and `--json` are mutually exclusive.

With `--out` the report opens in your default browser; without it the HTML is printed to stdout.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | usage error (including mixing `--stix`, `--html` and `--json`) |
| 2 | config error (unreadable or invalid `config.yaml`) |
| 3 | all sources failed |
| 4 | timeout |
