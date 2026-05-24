---
title: Troubleshooting
nav_order: 8
---

# Troubleshooting
{: .no_toc }

1. TOC
{:toc}

## Repository / target

**`Repository not found`** — Ensure the target directory exists under
`./repos/<name>/` and matches the `REPO=` flag exactly.

**Can't reach `localhost` from inside Docker** — use
`host.docker.internal` instead:

```bash
./dapper start URL=http://host.docker.internal:3000 REPO=repo-name
```

## Temporal / Docker

**`Temporal not ready`** — Wait for the health check, or inspect logs:

```bash
docker compose logs temporal
```

**Worker not processing** — Make sure the worker container is running:

```bash
docker compose ps
```

**Reset workflow state** — wipes Temporal data and volumes:

```bash
./dapper stop CLEAN=true
```

**Linux permission issues** — run Docker commands with `sudo`, or add your
user to the `docker` group.

## External tool dependencies

These tools enhance reconnaissance but Dapper can run without them in
testing mode:

- `nmap` — network scanning
- `subfinder` — subdomain discovery
- `whatweb` — web technology detection

Skip them with `PIPELINE_TESTING=true` during development:

```bash
./dapper start URL=https://your-app.com REPO=your-repo PIPELINE_TESTING=true
```

## Windows Antivirus false positives

Windows Defender may flag files in `xben-benchmark-results/` or
`deliverables/` as malware. These are **false positives** caused by exploit
code in the reports. Either:

- Add an exclusion for the Dapper directory in Windows Defender, or
- Run Dapper inside WSL2 / a Docker volume that Defender doesn't scan.

## Diagnostic UIs

```bash
# Temporal workflow history
open http://localhost:8233
```
