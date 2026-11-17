# Spamhaus / abuse.ch source migration (November 2026)

## Confirmed by Spamhaus support
- Feodo Tracker is retired following Operation Endgame. Do not start new Feodo streaming connections.
- Spamhaus Botnet C2 IPs (formerly BCL) is available through the Spamhaus Intelligence API, subject to access and licensing.
- The abuse.ch Commercial API provides Malware IoCs (formerly ThreatFox), Malware URLs and Malware Samples, subject to access and licensing.
- A Spamhaus account manager is expected to clarify permitted commercial use. No approval has been received yet.

## Safe changes in this pull request
- Remove Feodotracker from the active upstream WebSocket feed list.
- Mark its health state `retired` rather than falsely reporting it live.
- Keep existing Feodo observations and existing rebroadcast restrictions intact.
- Do not enable new commercial feeds or make public redistribution claims.

## Follow-up engineering checklist
- [ ] Confirm licensing, permitted public display, redistribution, retention, caching and attribution in writing.
- [ ] Confirm available authentication, rate limits, incremental retrieval and migration details.
- [ ] Check if existing URLhaus and ThreatFox WebSocket subscriptions remain contractually and technically available.
- [ ] Build a source-adapter interface for WebSocket streams vs query-only REST APIs.
- [ ] Add provider-specific schema validation, cursor handling, backoff and source health.
- [ ] Separate historical Feodo observations from current indicators in UI and reports.
- [ ] Add regression tests for retired source and feed health.
- [ ] After approval, implement Botnet C2 IPs and/or Malware IoCs adapters behind disabled-by-default configuration flags.
- [ ] Test in staging before any production deployment.

## Documentation
- https://docs.spamhaus.com/sia/docs/source/index.html
- https://abusech-docs.spamhaus.com/api-reference
- https://docs.spamhaus.com/real-time-feeds/docs/source/index.html

Note: Some public real-time documentation still mentions Feodo; the direct provider email is the more specific current status confirmation.