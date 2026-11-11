# Security and responsible reporting

Do not post credentials, private inventories, raw personal data or exploit payloads in public issues. Use GitHub's private vulnerability reporting option if enabled. If it is unavailable, open an issue requesting a private contact without including sensitive details.

NEXUS LIVE reads public feeds only. No active scanning, DNS resolution of observed domains, probing or exploitation belongs in the live collectors. External data is untrusted: byte/schema limits, bounded queues, explicit source gates and safe DOM text construction are required. The scanner directory is outside this change.

The API runs unprivileged behind Caddy. Keep all API, database and sidecar ports private. Configure the exact trusted Caddy peer address; never trust arbitrary visitor-supplied forwarding headers. CORS is not authentication or denial-of-service protection.

No secrets belong in commits, chat, logs or public evidence. New signal evidence is aggregate-only and expires with its event. Raw peer addresses and observed domains must not enter the public signal buffer. Source failures must never produce fabricated observations.

High or critical findings block release. Passing unit tests is not a security certification. This implementation is still awaiting independent review, deployment validation and device performance checks.

