# Recon Pipeline

A small Bash workflow for **explicitly authorized** bug-bounty scope and personal test labs.

## Run

```bash
./recon.sh example.com
```

The script asks you to type `AUTHORIZED` before it makes any network request. Do not confirm unless the exact domain is in the program's current scope or is your own lab.

## What it does

1. `subfinder` performs passive subdomain discovery.
2. `httpx-toolkit` checks which discovered hosts answer over HTTP or HTTPS.
3. `katana` crawls at most 50 live hosts, at depth 2 and for at most 2 minutes per host list, while extracting JavaScript-linked endpoints.
4. `summary.txt` lists counts and result filenames.

It does **not** perform port scans, fuzzing, exploit attempts, or vulnerability scanning. Nuclei is deliberately not part of this project.

## Read a run

Each run is isolated at `results/<domain>/<date-time>/`:

- `01-subdomains.txt`: unique passive subdomains
- `02-http-details.txt`: reachable URLs with status and title
- `02-live-hosts.txt`: normalized reachable URLs
- `02-selected-live-hosts.txt`: the capped set supplied to Katana
- `03-urls.txt`: unique discovered URLs/endpoints whose host is the target or one of its subdomains
- `03-javascript.txt`: in-scope JavaScript URLs (`.js`, `.mjs`, or `.cjs`, including query strings) filtered from the URL set
- `summary.txt`: counts and a compact index

## Optional API keys

No API key is required. To use provider-backed Subfinder sources, copy `.env.example` to `.env`, point `SUBFINDER_PROVIDER_CONFIG` at a separately protected provider YAML, and restrict both files to your account (`chmod 600`). Never paste secrets into the terminal or commit them.

## Safety limits

Change only `config/settings.conf` and only within the authorized program's rules. The scope confirmation is an intentional interactive gate; non-interactive runs fail closed.
