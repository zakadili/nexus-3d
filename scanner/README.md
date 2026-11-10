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

## Dashboard integration

After running the scanner, open the NEXUS website → **ASSESSMENT LAB** → **IMPORT NEXUS ACTIVE SCAN JSON** and select `nexus-scan.json`. The evidence is rendered in your browser without uploading it to a server.

## Optional CVE-specific configuration probe

Add `--verify-3des` to check TLS ports 443/8443 for negotiation of a 3DES cipher associated with **CVE-2016-2183 (SWEET32)**:

```bash
python3 scanner/nexus_scan.py --scope scanner/scope.example.json --targets 127.0.0.1 --ports 443 --verify-3des --output nexus-scan.json
```

A successful 3DES handshake establishes weak-cipher support, **not successful exploitation**. Failure to negotiate 3DES is reported as inconclusive (some OpenSSL builds do not support the cipher locally), never as a definitive negative. No exploit payloads are sent.
