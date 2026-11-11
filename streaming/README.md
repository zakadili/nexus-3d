# NEXUS SENTINEL — event-driven streaming backend

## Bronze-glade deployment

Public API: https://nexus-193-26-115-37.sslip.io/api/health. The homepage's Live Intelligence navigation opens the streaming panel; the globe retains its existing scheduled snapshots.

Run one API process only. PostgreSQL and the API each have a 256 MiB limit; PostgreSQL has a 48 MiB shared buffer and 20 connections, with a four-connection application pool. Caddy runs on the host and proxies only the listed public API and WebSocket routes. PostgreSQL has no published port. The API publishes only on loopback and runs as a non-root user with a read-only filesystem and dropped capabilities. `.env` is excluded from Git and the image build context.

`Caddyfile`, `nexus.service`, and `nexus-monitor.*` are the installed service definitions. Caddy manages public certificates and redirects HTTP to HTTPS. A local five-minute timer records readiness, RAM, disk, and container consumption in the bounded system journal; it is not an external paging service. Docker restart policies recover terminated containers. Readiness failures are recorded and do not automatically delete or recreate database storage.

Retention runs every minute: observations older than 48 hours or beyond the latest approximately 20,000 sequence positions are removed in 5,000-row batches. Large raw payloads over 8 KiB are replaced by an explicit omission marker and SHA-256 digest; normalized event fields remain. PostgreSQL reuses vacuumed space rather than shrinking its files. Logs rotate at 5 MiB × 2 for each container and Caddy. Provider gaps retain seven days of detail and a cumulative count. Public replay reports when its cursor predates local pruning. Public replay is buffered in the browser before newer broadcasts advance its cursor.

Spamhaus token refresh is shared and cached. Without credentials those feeds report `credentials_required`, and no connection is attempted. Raw redistribution remains disabled. IODA polls every 180 seconds with a durable checkpoint, five-minute overlap, one-hour recovery bound and up to five 1,000-record pages; exceeded recovery or pagination coverage is explicitly reported. CISA KEV is fetched daily. FIRST EPSS is fetched daily for the 100 most recently added KEVs; missing scores remain absent. Neither reference is counted as a live observation. No GeoIP/ASN enrichment is enabled.

Validation: `docker compose exec -T api python test_integration.py` creates an isolated temporary schema, checks persistence, deduplication, upstream/local cursors, retention, rate limiting, WebSocket replay/broadcast/reconnect and Origin rejection, then removes only that test schema. Test fixtures never enter the public production schema or its WebSocket process. GitHub Actions runs the same checks. Authorized provider replay and live feed semantics still require upstream credentials and actual source availability.

The server's secret file is `/opt/nexus/streaming/.env` (root-only). Enter provider credentials directly on the server, then recreate the API container. Public redistribution requires a separate review of the operator's provider authorization before changing `PUBLIC_REBROADCAST`.

This directory adds a **real ingestion service**, not a visual simulation. The current GitHub Pages globe remains a scheduled-snapshot view until a separately hosted backend is connected. No attack paths or GeoIP points are synthesized.

## Requirements

- A host with Docker Compose and a public HTTPS/WSS endpoint
- Valid Spamhaus RT credentials authorized for abuse.ch URLhaus, ThreatFox, and Feodo Tracker streams (or provider-approved tokens)
- Explicit permission to redistribute upstream data before setting `PUBLIC_REBROADCAST=true`
- DNS + TLS termination (Caddy/Nginx) for the stream hostname

## Deploy

```bash
cd streaming
cp .env.example .env
# Edit .env: Spamhaus user/password or token, ALLOWED_ORIGINS and DATABASE_URL
# Choose a strong password matching the database credential.
export POSTGRES_PASSWORD='YOUR_STRONG_PASSWORD'
docker compose up --build -d
curl http://127.0.0.1:8000/api/health
curl http://127.0.0.1:8000/api/windows
```

**Important:** the `DATABASE_URL` in `.env` should use the same password as `POSTGRES_PASSWORD`, URL-encoding special characters. The Compose service overrides DATABASE_URL using the interpolated database password. Run Compose with `POSTGRES_PASSWORD` in the environment or a local, untracked `.env` file. Never commit credentials.

Configure a TLS reverse proxy for `stream.yourdomain.example` → `http://127.0.0.1:8000`. Proxy must allow WebSocket Upgrade. Set `ALLOWED_ORIGINS=https://zakadili.github.io`. Avoid opening port 8000 publicly without TLS.

Only after the public API is deployed, edit `../stream-config.js`:

```javascript
export const STREAM_API = 'https://stream.yourdomain.example';
```

The homepage then opens `wss://stream.yourdomain.example/ws/live`. If the backend or an individual source is unavailable, its status reads unavailable/degraded, not zero activity. Raw abuse.ch records do **not** appear in the public WebSocket by default because redistribution authorization has not been established.

## Operational boundaries

- **Single instance only:** `uvicorn --workers 1`. The collector runs in-process; multiple workers would duplicate upstream connections. For multiple replicas, split ingestion into its own service and use a durable broker (Redis Streams or PostgreSQL LISTEN/NOTIFY + replay).
- **Durability:** events + upstream `_idx` commit transactionally. Upstream `_idx` and local browser `seq` are different cursors.
- **Resume:** after reconnection, replay starts at last committed `_idx + 1` when the provider still retains it. Expired provider history is logged in `coverage_gaps`. Gap-free replay cannot be guaranteed after long outages.
- **IODA:** 180-second alert lookback polling is near-real-time, not attack observation. A result hitting 1,000 items is flagged incomplete. Pagination is bounded to five pages; reaching the cap is reported as incomplete coverage.
- **CISA KEV:** daily reference catalog, never treated as live attacker activity.
- **GeoIP/ASN:** not performed by this initial backend. Accordingly, no new geographic points are drawn. Real map-layer changes require a vetted enrichment dataset, provenance timestamps, a public licensing review, and a handler in the SVG globe renderer. A feed-listed IP is not necessarily an attacking IP.
- **Latency:** streaming feed records may arrive within seconds once an upstream event is published; IODA is minutes; KEV is daily. Show upstream age and last-success separately.
- **Security:** restrict WebSocket Origin, enforce TLS, disable raw rebroadcast by default, monitor queue saturation, retain back-ups, and implement retention and database migrations. The included public API is a single-host prototype, not a high-availability service.
- **No fictional metrics:** rolling counters represent ingested records. They are not numbers of attacks, victims, infections or distinct malicious hosts.

## Useful commands

```bash
docker compose logs -f api
docker compose exec db psql -U nexus -d nexus -c   "SELECT feed_source,state,last_idx,last_received_at,gap_count FROM feed_state;"
docker compose exec db psql -U nexus -d nexus -c   "SELECT feed_source,count(*) FROM observations GROUP BY 1;"
```

## Validation

The GitHub Actions workflow runs Python and JavaScript syntax validation and verifies that the homepage includes the stream panel. The workflow also runs isolated PostgreSQL and WebSocket integration checks. Provider contracts, authorized live upstream replay, high load and external alerting remain outside those tests.

## Public five-minute collectors

PhishDestroy primary indicators (MIT, notice in PHISHDESTROY-LICENSE.txt) and SSLBL certificate indicators (CC0 under abuse.ch terms section 3.4) are checked every 300 seconds plus fetch time. The initial lists are snapshots; later additions and removals are detected list changes, not attacks observed by NEXUS. SSLBL C2 is retired and excluded. Spamhaus real-time records stay private while public redistribution is disabled.

`GET /api/public-snapshots` returns bounded samples, source licensing, current list sizes and last-check timestamps. It never returns private feed records. `GET /api/events?recent=true&limit=45` bootstraps recent public history on every page load, independently of the saved WebSocket resume cursor. Initial snapshot samples do not inflate arrival counters. Current lists refresh in the browser every minute; upstream polling is five minutes and does not guarantee upstream publication frequency.
