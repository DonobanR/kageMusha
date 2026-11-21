# Tranco API — Shape and PR 3a Decisions

Investigated 2026-11-09 against the live API.

## Endpoints

| Endpoint | Method | Returns | Auth | Rate limit |
|---|---|---|---|---|
| `/top-1m-id` | GET | List ID in plain text (e.g. `8P8NV`) | No | Not documented |
| `/top-1m.csv.zip` | GET | 307 → ZIP ~9.2MB with CSV (rank,domain) | No | Not documented |
| `/api/lists/date/latest` | GET | JSON: `list_id`, `download` URL, `created_on`, `configuration` | No | Not documented |
| `/download/{id}/1000000` | GET | CSV directly | No | Not documented |
| `/api/ranks/domain/{domain}` | GET | JSON: historical ranks (past 30 days) | No | 1 req/s |

## Key finding: "daily" list is a 30-day average

The standard daily list is NOT a single-day snapshot. Its configuration shows:
```json
{
  "combinationMethod": "dowdall",
  "startDate": "2026-10-10",
  "endDate": "2026-11-08",
  "providers": ["crux", "farsight", "majestic", "radar", "umbrella"]
}
```
It averages 5 rankings over ~30 days. This means:
- No need to choose weekly vs monthly — the daily list is already stable by design.
- A domain appearing in this list has been consistently popular, not a one-day spike.

## Cache flow for PR 3a

```
GET /top-1m-id → "8P8NV"
Compare with cached list_id
  ├─ Same → use cached CSV, skip download
  └─ Different → GET /top-1m.csv.zip → unzip → replace cache + update stored list_id
```

This replaces a naive 7-day TTL. The check is 5 bytes; the download is ~9.2MB only when needed.

## CSV format

```csv
1,google.com
2,googleapis.com
3,youtube.com
...
999999,example.test
1000000,last.example
```

Ordered by rank (line 1 = rank 1). No header row.

## Decisions closed for PR 3a

### 1. URL and freshness check
Use `/top-1m-id` to check for new list + `/top-1m.csv.zip` to download.
Not the two-step API flow (`/api/lists` then `/download/{id}`).

### 2. `--low-memory` = Option A (linear scan)
Tranco CSV is ordered by rank, not by domain. Binary search would require
reordering or a dual-cache. Linear scan of 1M lines (~30ms per lookup) is
acceptable: 300ms for 10 IOCs, 15s for 500 IOCs. The point of `--low-memory`
is functioning in 128MB containers, not speed.

### 3. Cache path = `os.UserCacheDir()`
Stdlib function. Returns:
- Windows: `%LOCALAPPDATA%`
- macOS: `~/Library/Caches`
- Linux: `$XDG_CACHE_HOME` or `~/.cache`

Full path: `{UserCacheDir}/kagemusha/tranco-1m.csv` + `tranco-list-id.txt`.

### 4. Testability = `NewWithPath(csvPath)`
Inject CSV path for tests, same pattern as `urlhaus.NewWithBase`.
Fixture: ~10 lines with fake domains at known ranks (1, 50000, 100001).

## FP semantics

"Not in Tranco" is NOT a signal of suspicion. It is absence of benign signal.
Most of the internet is not in the top 1M.

- Domain in top 100k → `FPEvidence{Status: Ok, Signals: [TrancoTop1M, TrancoTop100k]}`
- Domain in top 1M but not 100k → `FPEvidence{Status: Ok, Signals: [TrancoTop1M]}`
- Domain absent → `FPEvidence{Status: Ok, Signals: []}` (source responded, nothing to say)
- CSV load failure → `FPEvidence{Status: Error, Signals: []}`
