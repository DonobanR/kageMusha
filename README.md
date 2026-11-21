# Kagemusha

IOC triage engine for threat intelligence. Scores indicators against multiple threat feeds and false-positive sources, producing explainable verdicts with confidence levels. Go, one small dependency set (`yaml.v3`, `x/net/publicsuffix`), JSON, STIX 2.1 or HTML output.

## Quick start

```bash
git clone https://github.com/DonobanR/kagemusha.git
cd kagemusha
cp config.example.yaml config.yaml   # add your abuse.ch key
go build -o kagemusha ./cmd/kagemusha
./kagemusha scan 162.243.103.246
```

Get your free abuse.ch Auth-Key at https://auth.abuse.ch/
Get your free OTX API key at https://otx.alienvault.com/api

## Demo

```
$ ./kagemusha scan 162.243.103.246
```

Real output (captured 2026-11-21):

```json
{
  "target": "162.243.103.246",
  "type": "ipv4",
  "verdict": "suspicious",
  "confidence": 24,
  "fp_score": 0,
  "reasons": [
    {
      "code": "urlhaus_not_listed",
      "message": "Not listed in urlhaus"
    },
    {
      "code": "threatfox_listed",
      "message": "Listed in threatfox (family: Cobalt Strike)"
    },
    {
      "code": "feodo_listed",
      "message": "Listed in feodo (family: Emotet)"
    },
    {
      "code": "otx_listed",
      "message": "Listed in otx (50 pulse(s))"
    }
  ],
  "sources": [
    {
      "name": "urlhaus",
      "status": "not_listed"
    },
    {
      "name": "threatfox",
      "status": "ok",
      "detail": "malware family: Cobalt Strike | also: Emotet",
      "reference": "https://threatfox.abuse.ch/ioc/1840194",
      "first_seen": "2026-06-30T04:49:59Z"
    },
    {
      "name": "feodo",
      "status": "ok",
      "detail": "malware family: Emotet | C2 port 8080, status offline | CSV is 261 days old",
      "reference": "https://feodotracker.abuse.ch/browse/host/162.243.103.246/",
      "first_seen": "2022-06-04T21:24:53Z",
      "last_seen": "2026-03-07T00:00:00Z"
    },
    {
      "name": "otx",
      "status": "ok",
      "reference": "https://otx.alienvault.com/pulse/6b00b0ff5093bcbe2dac230e",
      "first_seen": "2022-10-11T13:14:18Z",
      "last_seen": "2026-11-20T20:43:43Z"
    }
  ]
}
```

**Why suspicious at 24%?** The IP is a known Emotet C2, but the evidence is old: the Feodo entry was last online in March 2026 and ThreatFox first saw it in June 2026. Evidence loses weight with a 30-day half-life for IPs (90 for domains and URLs), so there is no fresh anchor and the verdict is held at `suspicious` with low confidence. Compare with a freshly reported C2, which reaches `malicious`.

### STIX 2.1 output

```bash
./kagemusha --stix scan 162.243.103.246
```

Produces a STIX 2.1 Bundle with Indicator, Malware and Relationship objects. Import it into MISP, OpenCTI, or any STIX-compatible tool to visualize the threat graph. IDs are deterministic (UUID v5), so the same IOC always produces the same STIX objects for deduplication.

## How it decides

| Condition | Verdict |
|---|---|
| a **fresh anchor** and FP score < 60 | **malicious** (no score threshold) |
| threat score >= 30, or any anchor (fresh or stale) | **suspicious** (`historical` flag when only a stale anchor) |
| FP score >= 60 and no threat evidence | **benign** |
| otherwise | **unknown** |

The verdict says what a curated source asserts; the confidence says how much it is corroborated. A single fresh anchor is enough for `malicious`, but with one source (or one correlation group) confidence is capped at 60%.

An **anchor** is URLhaus, Feodo, or a ThreatFox entry that is `reporter = abuse_ch` + `threat_type = botnet_cc`. It is **fresh** when its age-decay factor is >= 0.5 (hashes never decay; evidence without a date is never fresh).

### Threat sources

| Source | Weight | Type | Coverage |
|---|---|---|---|
| Feodo Tracker | 40 (anchor) | CSV blocklist | IPv4 (confirmed C2s). Frozen since 2026-03. |
| URLhaus | 35 (anchor) | API | domains, IPs, URLs, hashes |
| ThreatFox | 30 (40 if anchor-grade entry) | API | domains, IPs, URLs, MD5, SHA-256 |
| OTX | 20 (secondary) | REST API | domains, IPs, URLs, hashes |

**Anchor gate:** without a fresh anchor the verdict can never be `malicious`, whatever the score. Secondary evidence alone (ThreatFox from third parties, OTX) tops out at `suspicious`.

### False-positive sources

| Source | Weight | Coverage |
|---|---|---|
| Tranco top 1M | 30 | domains |
| Tranco top 100k bonus | +30 | domains (top 100k subset) |

FP >= 60 (top 100k) vetoes `malicious`. Subdomains inherit the rank of their parent (`cdn.discordapp.com` → `discordapp.com`), except under public suffixes such as `github.io`, where each tenant is independent.

### Enrichment sources (context only, weight 0)

| Source | Coverage | Output |
|---|---|---|
| CDN/Cloud Ranges | IPv4 (Cloudflare + AWS) | `"Hosted in {Provider} (Cloud Infrastructure)"` |

Enrichment sources add context for the analyst without affecting the score. See [Why Cloud Hosting is Context, Not Innocence](#why-cloud-hosting-is-context-not-innocence).

### Confidence

Noisy-OR over the sources that voted (silence is not evidence against), with correlated sources grouped (URLhaus + ThreatFox count as one voter):

- **Single-voter cap:** 60. Confidence above 60 needs two independent voters (e.g. Feodo + URLhaus).
- **Suspicious scaling:** noisy-OR × 0.5 (max 49%). Unknown is always 0%.
- Age decay also scales each source's reliability.

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

## Flags

```
--abusech-auth-key   abuse.ch Auth-Key (overrides env/config)
--otx-api-key        AlienVault OTX API key (overrides env/config)
--out FILE           write output to file instead of stdout
--stix               STIX 2.1 bundle output
--json               JSON output (default)
--timeout DURATION   abort scan after duration (e.g. 30s, 2m)
--workers N          max concurrent IOCs (default 10)
--low-memory         linear scan for Tranco (~15 MB vs ~120 MB)
--verbose            print debug info to stderr
--version            print version and exit
```

## Concurrency (Pool A/B)

Kagemusha separates sources into two pools for batch scanning:

- **Pool A** (rate-limited): abuse.ch API sources (URLhaus, ThreatFox) share a 1 request/second token bucket. This prevents 429 errors when scanning incident-sized IOC lists.
- **Pool B** (unconstrained): Everything else — Feodo (local CSV), Tranco (local list), CDN (local CIDR cache) — runs with no rate limit.

Within each IOC, all applicable sources are queried concurrently (Pool A through the limiter, Pool B immediately). Multiple IOCs are processed in parallel up to `--workers` (default 10). Results always preserve input order.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | usage error |
| 2 | config error |
| 3 | all sources failed |
| 4 | timeout |

## Why Cloud Hosting is Context, Not Innocence

Kagemusha deliberately does **not** reduce threat scores for IPs hosted in cloud providers (AWS, Cloudflare, Azure, GCP, etc.). This is a core design decision rooted in CTI doctrine:

**Adversaries rent cloud infrastructure.** APT10 (Cloud Hopper) operated entirely from legitimate cloud service providers. Commodity malware operators routinely spin up VPS instances in AWS, Azure, and DigitalOcean for C2 servers. A cloud-hosted IP is not evidence of benignity — it is context.

The FOR578 (GCTI) principle applies: *Indicator - Context = Data*. Without context, an indicator is meaningless noise. But context does not equal innocence. Knowing an IP belongs to AWS tells the analyst *where* the infrastructure is, not *whether* it is malicious.

Kagemusha uses mathematics for triage (weighted scoring from threat intelligence feeds) and provides cloud hosting information as enrichment context so the human analyst can apply critical thinking. The `context` field in the JSON output carries this information without polluting the score.

```json
{
  "target": "104.16.132.229",
  "verdict": "unknown",
  "confidence": 0,
  "context": ["Hosted in Cloudflare (Cloud Infrastructure)"],
  "sources": [...]
}
```

The analyst sees the cloud hosting context and decides what it means for their investigation. The math stays clean.

## Limitations (v0.1)

1. A domain or IP reported **only by a third party in ThreatFox** stays `suspicious`, even if recent (only `abuse_ch` + `botnet_cc` entries are anchors).
2. **Hashes have only URLhaus as anchor.** ThreatFox hash entries are never anchor-grade.
3. **Feodo Tracker is frozen** since 2026-03 (5 entries).
4. **The malware family reported by OTX is not reliable** (derived from community pulse tags).
5. A subdomain of a top-100k domain inherits the FP veto even if the abuse is real on that subdomain.
6. **The HTML report shows every scanned IOC** (including `benign` and `unknown`) as a graph built from the STIX bundle, so it does not display the `historical` and `partial` flags, the `incomplete` reason or the cloud-hosting context; those are only in the JSON output.
7. **STIX output is minimal:** Indicator, Malware (abuse.ch sources only) and Relationship. No Sighting or Identity objects.
8. `--low-memory`: linear scan, ~30 ms per Tranco lookup, ~15 MB RAM. Default: O(1), ~120 MB.

## Requirements

- Go 1.27+
- abuse.ch Auth-Key (free): https://auth.abuse.ch/
- AlienVault OTX API key (free, optional): https://otx.alienvault.com/api

## License

Apache License 2.0, see [LICENSE](LICENSE). Copyright 2026 DonobanR.

Free to use at work, modify and redistribute, including commercially; the license adds an explicit patent grant. Contributions are welcome under the same license.
