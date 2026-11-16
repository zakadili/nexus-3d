# NEXUS SaaS architecture decision (draft)

## Decision
Evolve the existing public radar and streaming prototype into a **modular monolith with separate collectors and job workers**. Do not rewrite the globe or migrate the public GitHub Pages site as a prerequisite.

### Trust boundaries
- Public intelligence is **shared** and must retain source license, timestamps, provenance, completeness and coverage gaps.
- Customer data (organizations, verified assets, findings, alerts, reports, credentials) is **private** and always tenant-scoped.
- Public endpoints must never return customer assets, scans, or internal organization identifiers.
- Browser input and Origin headers are not authentication. Use a reviewed OIDC provider with server-side session validation; require server-side organization membership and role checks on every private request.
- Database RLS is defense-in-depth, not a replacement for API authorization. Application DB credentials must not own tables or have BYPASSRLS; use transaction-scoped `SET LOCAL app.organization_id` after verifying membership, and reset via transaction boundaries.
- Never accept an organization ID from an unauthenticated or unverified client as a trusted database context.
- No active scans without explicit ownership verification and approved scope; guard DNS resolution and outbound network destinations against SSRF and rebinding.

### Components
1. **Public site**: existing static map and research pages; no login required.
2. **Customer UI**: analyst and business views sharing API contracts.
3. **Private API**: identity, organizations, membership, assets, findings, audit trail; stateless request handlers.
4. **Collectors/workers**: licensed upstream ingestion, durable checkpointing, asset correlation, scheduled checks and notifications. Separate process lifecycle from HTTP server.
5. **PostgreSQL**: migrations, shared intelligence tables, tenant-isolated customer tables, durable jobs. Introduce a queue only when worker delivery semantics are defined.
6. **Observability**: structured logs without customer secrets, feed freshness, queue lag, API latency, errors, backup/restore drills and external alerting.

### Release sequence
- P0: reviewed identity provider and authorization threat model; database migration strategy and tenant-isolation integration tests; source-license matrix.
- P0: isolate collectors from the API, preserve idempotency/cursors and test reconnect/replay.
- P1: ownership verification and passive exposure correlation; evidence-backed reports with honest missing/stale coverage.
- P1: alerting, audit trail, retention/deletion, operational runbooks, staging, recovery and security review.
- P2: pilot users, measured performance, quotas, billing and enterprise features after demand validation.

### Migration safety
`streaming/migrations/0001_saas_foundation.sql` is a **proposal**, not auto-applied by Docker. Existing `streaming/schema.sql` continues to initialize the legacy feed database. Do not execute on production before review, backup and an isolated PostgreSQL integration test. The migration creates no users or access tokens and does not enable customer login.

### Acceptance gates
- Two organizations cannot read, change or delete each other's assets or findings through API or direct app DB role.
- A missing tenant context yields no rows, not global access; unauthorized writes fail.
- Feed errors cannot become “secure” or “no threats” customer claims.
- Workers and API can restart independently without losing committed feed cursor state.
- Backups are restored in staging; source permissions allow each intended commercial use.
