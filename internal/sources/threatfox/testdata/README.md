# ThreatFox Testdata

Real responses captured from the ThreatFox API (`/api/v1/` with `search_ioc`).
The google.com fixture was trimmed from 32 entries to 4 representative ones.

| File | Search term | Expected status | Why |
|---|---|---|---|
| `search_ioc_162_243_103_246.json` | 162.243.103.246 | `ok` | ip:port entries match bare IP |
| `search_ioc_google_com.json` | google.com | `not_listed` | All entries are subdomains or unrelated domains |

| `search_ioc_13_233_232_1.json` | 13.233.232.1 | `ok`, anchor | 2 `anonymous` entries + 1 `abuse_ch` entry (2034929); anchor derives only from the abuse_ch one |
| `search_ioc_hash_md5_e39950f0.json` | e39950f0b39918d0fb7e880932f73812 | `ok`, not anchor | `search_ioc` with a hash term returns the sample entry (`ioc_type` md5_hash, `threat_type` payload, reporter `Grim`) |

Captured: 2026-11-20 (first two), 2026-11-21 (13.233.232.1), untouched raw API output.
