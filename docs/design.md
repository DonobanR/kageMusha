# Design notes

Background for [README.md](../README.md): how confidence is computed, how scans run concurrently, and why cloud hosting is only context.

## Confidence

Noisy-OR over the sources that voted (silence is not evidence against), with correlated sources grouped. URLhaus, ThreatFox and Feodo all come from abuse.ch and count as **one** voter:

- **Single-voter cap:** 60. Confidence above 60 needs two independent voters, for example any abuse.ch source plus OTX.
- **Suspicious scaling:** noisy-OR × 0.5 (max 49%). Unknown is always 0%.
- Age decay also scales each source's reliability.

## Enrichment sources (context only, weight 0)

| Source | Coverage | Output |
|---|---|---|
| CDN/Cloud Ranges | IPv4 (Cloudflare + AWS) | `"Hosted in {Provider} (Cloud Infrastructure)"` |

Enrichment sources add context for the analyst without affecting the score. See [Why Cloud Hosting is Context, Not Innocence](#why-cloud-hosting-is-context-not-innocence).

## Concurrency (Pool A/B)

Kagemusha separates sources into two pools for batch scanning:

- **Pool A** (rate-limited): abuse.ch API sources (URLhaus, ThreatFox) share a 1 request/second token bucket. This prevents 429 errors when scanning incident-sized IOC lists.
- **Pool B** (OTX): AlienVault OTX has its own limiter of 2 requests/second, and retries on HTTP 429 (honoring `Retry-After`, up to 30 s, within `--timeout`).
- **Local sources** (no limit): Feodo (local CSV), Tranco (local list), CDN (local CIDR cache) do not make a request per IOC.

Within each IOC, all applicable sources are queried concurrently (each API source through its limiter, local sources immediately). Multiple IOCs are processed in parallel up to `--workers` (default 10). Results always preserve input order.

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
