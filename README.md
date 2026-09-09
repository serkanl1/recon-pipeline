# Recon Pipeline

A small Bash workflow for **explicitly authorized** bug-bounty scope and personal test labs.

## Run

```bash
./recon.sh example.com
```

The script asks you to type `AUTHORIZED` before it makes any network request. Do not confirm unless the exact domain is in the program's current scope or is your own lab.

## What it does

1. `subfinder` performs passive subdomain discovery. If `assetfinder` is installed, its results are merged in as a second passive source.
2. If `dnsx` is installed, discovered subdomains are DNS-resolved first and dead entries are dropped before the HTTP check; skipped automatically if `dnsx` isn't present.
3. `httpx-toolkit` checks which discovered hosts answer over HTTP or HTTPS.
4. `katana` crawls at most 50 live hosts, at depth 2 and for at most 2 minutes per host list, while extracting JavaScript-linked endpoints. If `gau` (or, as a fallback, `waybackurls`) is installed, historical URLs from web archives are merged in before scope filtering.
5. `summary.txt` lists counts, which optional tools ran, and result filenames.

Every discovery step — passive or archive-based — is re-filtered against the target's own scope check afterward, so an optional tool being installed never widens what ends up in the non-raw result files.

It does **not** perform port scans, fuzzing, exploit attempts, or vulnerability scanning. Nuclei is deliberately not part of this project.

## Optional tools

None of these are required — the pipeline runs with just `subfinder`, `httpx-toolkit`, and `katana` if that's all you have. Installing any of the following is picked up automatically on the next run, no config change needed:

| Tool | Adds |
|---|---|
| `assetfinder` | extra passive subdomain source |
| `dnsx` | DNS-resolution filter before the HTTP check |
| `gau` | historical/archive URL discovery (preferred over waybackurls if both are present) |
| `waybackurls` | historical/archive URL discovery (used if `gau` isn't installed) |

`summary.txt` records which of these actually ran for a given scan.

## Read a run

Each run is isolated at `results/<domain>/<date-time>/`:

- `01-subdomains-raw.txt`: raw, **unfiltered** subfinder/assetfinder output — kept for transparency; may contain out-of-scope entries before the scope check runs
- `01-subdomains.txt`: unique passive subdomains, filtered to the target and its subdomains only
- `01-resolved-subdomains.txt`: subdomains that resolved via `dnsx` (empty if `dnsx` isn't installed)
- `02-http-details.txt`: reachable URLs with status and title
- `02-live-hosts.txt`: normalized reachable URLs
- `02-selected-live-hosts.txt`: the capped set supplied to Katana
- `03-urls-raw.txt`: raw, **unfiltered** katana/gau/waybackurls output — kept for transparency
- `03-urls.txt`: unique discovered URLs/endpoints whose host is the target or one of its subdomains
- `03-javascript.txt`: in-scope JavaScript URLs (`.js`, `.mjs`, or `.cjs`, including query strings) filtered from the URL set
- `summary.txt`: counts, optional-tool usage, and a compact index

If you ever see something in the results that looks out of scope, check whether it came from a `-raw.txt` file first — those are intentionally pre-filter. The console log for every scan also prints a `Scope filter: kept X of Y raw entries for <target>` line for each filtering step, so you can confirm exactly how much was dropped and where.

## Optional API keys

No API key is required. To use provider-backed Subfinder sources, copy `.env.example` to `.env`, point `SUBFINDER_PROVIDER_CONFIG` at a separately protected provider YAML, and restrict both files to your account (`chmod 600`). Never paste secrets into the terminal or commit them.

## Safety limits

Change only `config/settings.conf` and only within the authorized program's rules. The scope confirmation is an intentional interactive gate; non-interactive runs fail closed.
