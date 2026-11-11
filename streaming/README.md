# NEXUS SENTINEL — event-driven streaming backend

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
- **IODA:** 180-second alert lookback polling is near-real-time, not attack observation. A result hitting 1,000 items is flagged incomplete. Add full pagination before claiming exhaustive coverage.
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

The GitHub Actions workflow runs Python and JavaScript syntax validation and verifies that the homepage includes the stream panel. Live connectivity, provider contracts, replay behavior, IODA pagination, DB schema migrations, load, licensing, and full frontend integration require further testing before a production launch.
