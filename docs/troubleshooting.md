---
title: Troubleshooting
parent: Resources
nav_order: 3
permalink: /resources/troubleshooting
---

# Troubleshooting
{: .no_toc }

1. TOC
{:toc}

This guide is organized as **problem → cause → fix**. Find the symptom you're
seeing, confirm the cause, and apply the fix. Most issues fall into Docker
startup, Temporal orchestration, or reaching the target.

---

## Docker & startup

### Dapper won't start / "Cannot connect to the Docker daemon"

**Cause.** Docker isn't running, or your shell can't reach the Docker socket.

**Fix.** Start Docker Desktop (macOS/Windows) or the daemon (Linux:
`sudo systemctl start docker`), then confirm it responds:

```bash
docker info        # should print server details, not an error
docker compose ps  # should list Dapper containers
```

### Code changes aren't being picked up

**Cause.** Docker is reusing a cached image layer.

**Fix.** Force a clean rebuild:

```bash
./dapper start URL=https://your-app.com REPO=your-repo REBUILD=true
```

### "No space left on device" / large image pulls stall

**Cause.** Dapper's image bundles the security toolchain and a browser, so the
first build pulls and stores several GB. A full Docker disk also surfaces as
mysterious build or container-start failures.

**Fix.** Reclaim space and retry. `./dapper stop CLEAN=true` removes Dapper's
own volumes; `docker system prune` clears unused images and build cache
across all projects:

```bash
docker system df            # see what's using space
./dapper stop CLEAN=true    # drop Dapper's volumes
docker system prune -a      # reclaim unused images/cache (all projects)
```

On macOS/Windows, also raise the Docker Desktop disk-image size limit in
**Settings → Resources** if pulls keep failing.

---

## Temporal orchestration

### `Temporal not ready`

**Cause.** The Temporal server container hasn't finished its health check yet,
or failed to come up.

**Fix.** Give it a moment, then inspect its logs:

```bash
docker compose logs temporal
```

The Temporal Web UI at <http://localhost:8233> is another quick health signal —
if it loads, the server is up.

### Worker not processing / workflow appears stuck

**Cause.** The worker container that executes activities isn't running, so
queued work never gets picked up.

**Fix.** Check container status and tail the worker logs:

```bash
docker compose ps     # the worker should be "running"/"healthy"
./dapper logs         # real-time worker output
```

If the worker is down, a restart re-attaches it. Because the pipeline is
durable, an in-flight workflow **resumes from its last checkpoint** rather than
starting over.

### Reset all workflow state

**Cause.** You want a clean slate — corrupted state, leftover test runs, or
you're done debugging.

**Fix.** This wipes Temporal data **and all volumes**:

```bash
./dapper stop CLEAN=true
```

Plain `./dapper stop` (without `CLEAN=true`) stops the containers but
**preserves** workflow data so you can resume later.

---

## Repository & target

### `Repository not found`

**Cause.** The `REPO=` value doesn't match a folder inside `./repos/`, which is
where Dapper expects target code.

**Fix.** Place (or clone) the repo under `./repos/` and pass the **folder name**
exactly:

```bash
git clone https://github.com/your-org/your-repo.git ./repos/your-repo
./dapper start URL=https://your-app.com REPO=your-repo
```

For monorepos, clone the single repo; for multi-repo apps, create one folder
under `./repos/` and clone the frontend/backend/API into it.

### Local target is unreachable

**Cause.** Containers can't resolve `localhost` to your host machine —
`localhost` inside the container points at the container itself.

**Fix.** Use `host.docker.internal` in the URL:

```bash
./dapper start URL=http://host.docker.internal:3000 REPO=repo-name
```

---

## External reconnaissance tools

### Missing `nmap` / `subfinder` / `whatweb`

**Cause.** These recon tools enhance the discovery phase. They're bundled in the
Docker image, but a custom or stripped environment may lack them.

**Fix.** They're optional. Skip external tooling (and use minimal prompts and
fast retries) for development with:

```bash
./dapper start URL=https://your-app.com REPO=your-repo PIPELINE_TESTING=true
```

| Tool | Purpose |
|:-----|:--------|
| `nmap` | Network port scanning |
| `subfinder` | Subdomain discovery |
| `whatweb` | Web technology fingerprinting |

---

## Linux: Docker socket & permissions

### "Permission denied" on the Docker socket or output files

**Cause.** On native Linux, your user may not have access to the Docker socket,
and files written by the container can be owned by root.

**Fix.** Either run the `./dapper` commands with `sudo`, or add your user to the
`docker` group so the socket is accessible without elevation:

```bash
sudo usermod -aG docker "$USER"   # then log out and back in
```

If output files under `./audit-logs/` end up root-owned, `chown` them back to
your user.

---

## Windows antivirus false positives

**Cause.** Windows Defender flags files in `xben-benchmark-results/` or
`deliverables/` as malware — these are **false positives** triggered by the real
exploit code embedded in the reports.

**Fix.** Add an exclusion for the Dapper directory in Windows Defender, or run
Dapper inside WSL2 / a Docker volume that Defender doesn't scan.

---

## Diagnostic UIs & quick commands

```bash
./dapper logs                   # real-time worker logs
./dapper query ID=<workflow-id> # progress of a specific workflow
docker compose ps               # container status
open http://localhost:8233      # Temporal workflow history (Web UI)
```
