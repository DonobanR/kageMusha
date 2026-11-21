# URLhaus Testdata

Real responses captured from the URLhaus API (`https://urlhaus-api.abuse.ch/v1/`),
captured 2026-11-21 with an Auth-Key (not stored here).

| File | Endpoint / request | Notes |
|---|---|---|
| `url_123_130_64_237_59149_i.json` | `POST /url/` `url=http://123.130.64.237:59149/i` | Untouched. `tags` = `["32-bit","elf","mips","Mozi"]`; `payloads[].signature` null; no top-level `urls` array. |
| `payload_md5_59ce0bab.json` | `POST /payload/` `md5_hash=59ce0baba11893f90527fc951ac69912` | Trimmed: the `urls` array (1000 entries, `url_count` 761641) cut to the first 3. Everything else untouched. `signature` is null. Top-level `firstseen`/`lastseen`; URL entries use `firstseen`/`lastseen`, not `date_added`. |
| `url_194_180_49_139_offline.json` | `POST /url/` `url=http://194.180.49.139/f2q2kke5aadloo4aasdjjjfirbmw/0xh0roxxnavebusyoo.arm7` | Untouched. `url_status` offline, `last_online` is `"2023-10-03 20:XX:XX UTC"` (time of day masked by URLhaus), tags `["elf","mirai"]`. |
