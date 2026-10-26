# INDEX

| Path | Purpose |
|---|---|
| `README.md` | Project title |
| `CollectionOfBlockingUrls.txt` | Upstream source lists (one URL per line); input for the monthly build |
| `blocklist.txt` | Generated monthly from the sources by the GitHub Action (do not edit by hand) |
| `CustomBlockList.txt` | Manually maintained domains; subscribed separately in Pi-hole |
| `RegExBlockers.txt` | Pi-hole regex blocking rules |
| `noDupes.txt` | One-off cleaned snapshot of the merged sources (not auto-updated) |
| `cleaned.txt` | Older cleaned snapshot (not auto-updated) |
| `AllDemBlocks.txt`, `AllDemBlocksSorted.txt` | Original raw merged snapshots (not auto-updated) |
| `scripts/build_blocklist.py` | Downloads the sources, extracts valid domains, dedupes, writes `blocklist.txt` |
| `.github/workflows/update-blocklist.yml` | Monthly (1st, 03:17 UTC) + manual run; opens a PR on `bot/update-blocklist` |
