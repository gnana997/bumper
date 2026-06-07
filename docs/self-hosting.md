# Self-hosting the Advisor

bumper's Terraform scanner is **fully offline** — it never needs a network. The only hosted
piece is the **[Advisor](api.md)**: the knowledge/CVE/malware service that backs `bumper deps`
and the agent's MCP lookups. The public instance at `advisor.bumper.sh` is
**lookup-not-upload** (only package coordinates ever leave your machine, and request bodies
aren't logged). Self-host when you want **even those coordinates to stay in-house**, an
air-gapped network, or full control over the data and uptime.

- [What you get](#what-you-get)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Verify it's working](#verify-its-working)
- [Point bumper at your instance](#point-bumper-at-your-instance)
- [Exposing it beyond localhost](#exposing-it-beyond-localhost)
- [Keeping the data fresh](#keeping-the-data-fresh)
- [Sizing & tuning](#sizing--tuning)
- [AI insights (optional)](#ai-insights-optional)
- [Upgrading](#upgrading)
- [Troubleshooting](#troubleshooting)

## What you get

The Advisor is the open-source **`bumper-advisor`** repo (Apache-2.0). A self-hosted instance
serves the same REST + MCP API as the public one:

- the **federated IaC catalog** (Trivy / Checkov / KICS / Prowler + bumper's enforced rules),
  pulled from the Go repo's rolling `catalog-latest` artifact;
- a **CVE/malware mirror** built from [OSV](https://osv.dev) — language ecosystems **and**
  Linux distros, including `MAL-` known-malicious advisories.

This is the **deterministic data the gate uses** — complete on its own. The **AI insights**
(plain-English explanations) are a separate, optional enrichment step that a fresh self-host
does **not** include; see [AI insights](#ai-insights-optional).

## Requirements

- **Docker** + **Docker Compose v2** (`docker compose`, not the legacy `docker-compose`).
- **Disk:** the full CVE mirror is **~4 GB** of Postgres data (persisted in a named volume).
- **RAM:** Postgres is the sink (HNSW vector index + ~3.4 M affected-version rows). Defaults
  are sized for a ~31 GB box; on a smaller VPS, turn the memory knobs down (see
  [Sizing & tuning](#sizing--tuning)). A comfortable full-set host is **~4 vCPU / 8–16 GB**;
  you can run much smaller by [limiting ecosystems](#sizing--tuning).
- **No GPU, no API key** — the embedding model is a numpy-only static model baked into the
  image.

The Advisor does **not** need the Docker socket and runs as an unprivileged user — safe to
run on a shared host.

## Quick start

```sh
git clone https://github.com/gnana997/bumper-advisor
cd bumper-advisor

cp .env.example .env
# edit .env — at minimum set a real POSTGRES_PASSWORD

docker compose up -d --build
```

On first boot, four things happen in order:

1. **`postgres`** starts (pgvector) and becomes healthy.
2. **`init`** loads the IaC catalog (downloads `catalog-latest`, ~seconds).
3. **`advisor`** starts serving on **`127.0.0.1:8000`** — `search`/`rule` work immediately.
4. **`cve-sync`** runs the **initial OSV mirror** in the background — **~13 minutes** for the
   full set — then exits. The daily **`scheduler`** keeps it fresh from then on.

> Until the first CVE sync **commits**, `lookup_cve` / `bumper deps` return
> `status: unavailable` — **never a false "clean."** Watch progress with
> `docker compose logs -f cve-sync`.

## Verify it's working

```sh
curl -s http://localhost:8000/healthz | jq
```

```jsonc
{
  "status": "ok",
  "model": "minishlab/potion-retrieval-32M",
  "corpora": { "iac": 2707, "cve_search": 78625, "cve_affected": 3419647 },
  "synced": { "cve_synced_at": "2026-06-07 10:34:21+00", "iac_synced_at": "2026-06-07 10:42:30+00" },
  "cache": { "hits": 0, "misses": 0, "size": 0 }
}
```

A non-zero `cve_affected` and a `cve_synced_at` timestamp mean the mirror is live. Try a real
lookup:

```sh
curl "http://localhost:8000/cve/lookup?ecosystem=npm&package=lodash&version=4.17.4"
```

## Point bumper at your instance

Anywhere bumper talks to the Advisor, override the base URL (default
`https://advisor.bumper.sh`). Three ways:

```sh
# 1) one-off, per command
bumper deps --advisor-url http://localhost:8000 package-lock.json

# 2) environment (CLI + hooks)
export BUMPER_ADVISOR_URL=http://localhost:8000
bumper deps

# 3) bake it into the agent wiring
bumper init --advisor-url http://localhost:8000
```

For the **MCP**, point your agent at `<base>/mcp` — e.g. `http://localhost:8000/mcp` in
`.mcp.json` / `.augment/settings.json` (or `bumper init --advisor-url …` writes it for you):

```json
{ "mcpServers": { "bumper-advisor": { "type": "http", "url": "http://localhost:8000/mcp" } } }
```

## Exposing it beyond localhost

The `advisor` port is bound to **loopback** (`127.0.0.1:8000`) on purpose. To reach it from
other machines:

- **Reverse proxy (recommended).** Put nginx/Caddy/Traefik in front, terminate TLS, and
  proxy to `127.0.0.1:8000`. The API is read-only and knowledge-only, but you still want
  TLS + your own access controls in front of it.
- **A tunnel** (Cloudflare Tunnel, Tailscale Funnel, etc.) also works — run its connector as
  an extra container pointing at `advisor:8000`.

Whichever you pick, **set `ADVISOR_ALLOWED_HOSTS`** to the public hostname clients will use
(e.g. `advisor.example.com`) — otherwise the MCP transport rejects them with a 421.

`/scan` is rate-limited per network via the bundled Redis (`SCAN_RATE_LIMIT`, default
`40/minute`) so a single caller can't pin the box; the single-lookup GET endpoints aren't
limited (run the CLI locally for unlimited full-tree scans).

## Keeping the data fresh

The **`scheduler`** service runs container-native cron (supercronic — **no Docker socket**)
on a fixed UTC schedule (`scripts/crontab`):

- `03:00` — refresh the CVE/OSV mirror (`sync_cve_pg.py`), **zero-downtime** (it builds into
  staging tables and atomically swaps, so lookups never see an empty mirror).
- `03:30` — refresh the IaC catalog (`sync_iac.py`) from `CATALOG_URL` (the Go repo's
  `catalog-latest`).

A freshness guard (`CVE_MIN_SYNC_AGE_HOURS`, default 20) makes a restart skip a re-sync if the
data is still recent. Point `CATALOG_URL` at your own mirror of the artifact if you don't want
to fetch from GitHub.

## Sizing & tuning

All knobs are environment overrides in `docker-compose.yml`:

| Env | Default | What |
| --- | --- | --- |
| `CVE_ECOSYSTEMS` | *(empty = all)* | Limit the mirror, e.g. `PyPI,npm,Go`. **The biggest lever** — drop the Linux distros and the DB shrinks dramatically. |
| `PG_SHARED_BUFFERS` | `8GB` | Postgres page cache (~25% of RAM). Lower it on a small VPS (e.g. `1GB`). |
| `PG_EFFECTIVE_CACHE` | `24GB` | Planner hint (~75% of RAM). |
| `PG_MAINT_WORK_MEM` | `2GB` | Speeds the nightly HNSW reindex. |
| `PG_WORK_MEM` | `64MB` | Per sort/hash node. |
| `PG_SHM_SIZE` | `2gb` | `/dev/shm` for Postgres. The reindex runs single-threaded, so this only matters for parallel queries. |
| `WORKERS` | `2` | uvicorn workers for the `advisor` service. |
| `SCAN_RATE_LIMIT` | `40/minute` | Per-network limit on `/scan`. |

**Small VPS recipe:** set `CVE_ECOSYSTEMS=PyPI,npm` (or just the ecosystems you use),
`PG_SHARED_BUFFERS=1GB`, `PG_EFFECTIVE_CACHE=3GB` — that runs comfortably in ~2 vCPU / 4 GB.

## AI insights (optional)

The plain-English `ai_insight` blocks are the **hosted Advisor's value-add** — precomputed by
an enrichment pipeline that is **not** part of the open-source distribution. A self-hosted
instance therefore serves the **complete deterministic data** (rules, CVEs, malware — what the
gate actually uses) with `has_ai_insight: false` on every record.

That's by design, not a missing feature: the insights are an **explanation layer**, never part
of any pass/fail decision. If you want them, use the hosted Advisor at `advisor.bumper.sh` (or
layer your own enrichment over the open data).

## Upgrading

```sh
cd bumper-advisor
git pull
docker compose up -d --build
```

The `pgdata` volume persists across rebuilds, so the mirror isn't re-synced unless it's stale
(per `CVE_MIN_SYNC_AGE_HOURS`). To wipe and start clean: `docker compose down -v`.

## Troubleshooting

- **`lookup_cve` / `bumper deps` returns `unavailable`** — the first CVE sync hasn't committed
  yet. `docker compose logs -f cve-sync`; it's ~13 min for the full set.
- **First sync looks "stuck" after `embedded N/N`** — that's the silent HNSW index build +
  VACUUM tail (minutes; logs nothing until done). Not a hang.
- **`DiskFull: could not resize shared memory segment`** — `/dev/shm` is too small for a
  parallel index build. The sync already forces a single-threaded reindex, so this shouldn't
  occur; if it does on a custom setup, raise `PG_SHM_SIZE`.
- **`healthz` shows `cve_affected: 0`** — the mirror isn't loaded; check `cve-sync` logs and
  that Postgres is healthy.
- **The advisor can't reach Postgres** — it talks over the compose network; don't set a
  host-published DB port. `DATABASE_URL` is wired automatically from `POSTGRES_PASSWORD`.

See [api.md](api.md) for the full endpoint reference and [mcp.md](mcp.md) for the MCP tools.
