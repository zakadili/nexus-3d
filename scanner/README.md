# NEXUS Active Scanner (first milestone)

A real, local Python active scanner for **explicitly authorized IP ranges**. No third-party packages required.

## Try on your own machine

Run a local HTTP server in another terminal:

```bash
python3 -m http.server 8080
```

Then:

```bash
python3 scanner/nexus_scan.py --scope scanner/scope.example.json --targets 127.0.0.1 --ports 8080 --output nexus-scan.json
```

The JSON output includes TCP connect results, HTTP response status and security header evidence. TLS checks are included for ports 443/8443.

## Scan an authorized lab

Create a scope JSON file with explicit `allowed_cidrs`, e.g. `["10.10.10.0/24"]`, and supply **literal IP addresses** via `--targets`. The tool refuses out-of-scope targets, caps each run at 32 targets and 32 ports, and uses four concurrent connection attempts per target.

## What this verifies

- TCP port reachable/open through a successful connect
- TLS handshake/cipher observation (not certificate identity validation)
- HTTP response status and presence/absence of common defensive headers

Missing headers are configuration observations, **not proof of exploitable vulnerabilities**. No exploit payloads, brute force, stealth, or arbitrary internet scanning are included. This CLI is not yet connected to the browser dashboard; its JSON output is a foundation for that integration.
