# NEXUS SENTINEL — SMB pilot (proposed, not launched)

## Mission
Help small and medium-sized businesses understand **their verified external exposure** and prioritize remediation using attributable, time-stamped evidence. NEXUS is not a penetration test, security certification, breach guarantee, or continuous monitoring service until those capabilities are implemented and validated.

## First customer
An organization with approximately 10–200 employees and at least one internet-facing domain, initially approached in Morocco. The first milestone is **five consenting pilot organizations**, not five fabricated dashboards or five paid subscriptions.

## Minimum trustworthy workflow
1. **Invite and consent:** document legal entity, administrator, contact, authorized domains, permitted activities, retention and deletion expectations.
2. **Verify domain control:** issue a random `nexus-verification=...` TXT token for `_nexus-verify.<domain>`; validate from server-side DNS; record verification time and expiry. DNS control does **not** authorize scanning unrelated infrastructure or third-party hosting.
3. **Inventory approved assets:** start with the verified domain and explicitly approved subdomains. No automatic wildcard authorization.
4. **Collect passive evidence:** public DNS, HTTPS certificate metadata and permitted intelligence datasets, respecting licenses and source rate limits. Label gaps and timestamps. Do not equate a CVE listing with an affected asset.
5. **Review findings:** distinguish confirmed evidence, potential exposure requiring validation, and unknown. Include source, observation time, affected asset, confidence and recommended next step.
6. **Deliver a pilot report:** clear executive summary, technical evidence, remediation guidance and an explicit coverage/limitations section. No fabricated scores.

## Pilot acceptance criteria
- Five organizations consent in writing and verify at least one domain each.
- No customer can read another customer's assets, tokens or reports (tenant isolation tests).
- Ownership verification is time-limited, revocable and rechecked.
- Every report finding has a traceable observation and method; no unsupported vulnerability claims.
- Errors and missing sources remain visible, not silently labeled safe.
- Authorized scope is enforced before any active probing; active scanning is disabled by default.
- Deletion/export, authentication, audit logs, backups and security incident procedures tested before storing real customer data.
- Billing remains **off** until pilot value, source terms, privacy and support obligations are validated.

## What this PR actually delivers
`pilot/domain-verification.mjs` is a **server-side proof-of-control primitive** and unit tests, not an exposed API, authenticated onboarding, persistent ownership ledger, or production-ready tenant system. It performs only DNS TXT lookups. Do not deploy it as a customer-facing service until authentication, token hashing, expiration, rate limits, audit trails, tenant isolation and operational safeguards are implemented.

## Commercial hypothesis
Starter €39/month, Business €99/month are **testing assumptions**, not published prices or an active offer. Interview the first five pilots before deciding plans.
