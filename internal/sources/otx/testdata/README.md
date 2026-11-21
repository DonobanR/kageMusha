# OTX Testdata

Real responses captured from the OTX API (`/api/v1/indicators/.../general`),
trimmed: pulse arrays cut to 2-3 entries and per-pulse fields reduced to
`id`, `name`, `tags`, `created`. The `validation` and `pulse_info.count`
fields are intact from the original response.

| File | IOC | Expected status | Key validation sources |
|---|---|---|---|
| `domain_amazon_com_whitelisted.json` | amazon.com | `suppressed` | akamai, alexa, majestic, whitelist |
| `domain_google_com_whitelisted.json` | google.com | `suppressed` | ad_network, akamai, alexa, false_positive, majestic, whitelist |
| `ipv4_8_8_8_8_whitelisted.json` | 8.8.8.8 | `suppressed` | false_positive, whitelist |
| `ipv4_13_107_42_14_cloud.json` | 13.107.42.14 | `ok` | cloud (not suppressed) |

Captured: 2026-11-20.
