#!/usr/bin/env python3
"""NEXUS scoped active scanner: safe service and web configuration verification."""
import argparse
import concurrent.futures
import datetime
import http.client
import ipaddress
import json
import socket
import ssl
import time
from pathlib import Path
from verify import verify_3des

DEFAULT_PORTS = (22, 80, 443, 8080, 8443, 3306, 5432, 3389)
MAX_TARGETS = 32
MAX_PORTS = 32

def scoped_ip(target, networks):
    """Require a literal IP inside an explicitly configured scope."""
    ip = ipaddress.ip_address(target)
    if not any(ip in net for net in networks):
        raise ValueError(f"{ip} is outside the approved CIDR scope")
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback and not any(net.is_loopback for net in networks):
        raise ValueError("Unsupported target")
    return ip

def check_port(ip, port, timeout):
    try:
        with socket.create_connection((str(ip), port), timeout=timeout):
            return {"port": port, "state": "open"}
    except (OSError, TimeoutError):
        return {"port": port, "state": "closed_or_filtered"}

def tls_check(ip, port, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((str(ip), port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=None) as sock:
                version = sock.version()
                return {"check": "tls_negotiation", "status": "observed", "evidence": {"version": version, "cipher": sock.cipher()[0] if sock.cipher() else None}, "note": "Certificate identity is not validated by this probe."}
    except (OSError, ssl.SSLError) as exc:
        return {"check": "tls_negotiation", "status": "inconclusive", "reason": type(exc).__name__}

def web_checks(ip, port, timeout):
    secure = port in (443, 8443)
    connection = (http.client.HTTPSConnection if secure else http.client.HTTPConnection)(str(ip), port, timeout=timeout, context=ssl._create_unverified_context()) if secure else http.client.HTTPConnection(str(ip), port, timeout=timeout)
    try:
        connection.request("HEAD", "/", headers={"User-Agent": "NEXUS-Scoped-Audit/1.0", "Connection": "close"})
        response = connection.getresponse()
        headers = {k.lower(): v for k, v in response.getheaders()}
        findings = []
        for key in ("content-security-policy", "x-content-type-options", "referrer-policy"):
            findings.append({"check": "http_header_" + key, "status": "present" if key in headers else "missing", "evidence": {"header": key, "value": headers.get(key)}})
        if secure:
            findings.append({"check": "hsts", "status": "present" if "strict-transport-security" in headers else "missing", "evidence": {"value": headers.get("strict-transport-security")}})
        return {"status_code": response.status, "server": headers.get("server"), "findings": findings}
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        return {"error": type(exc).__name__, "findings": []}
    finally:
        connection.close()

def run(args):
    scope = json.loads(Path(args.scope).read_text(encoding="utf-8"))
    networks = [ipaddress.ip_network(item, strict=False) for item in scope["allowed_cidrs"]]
    if not networks:
        raise ValueError("At least one CIDR is required")
    if len(args.targets) > MAX_TARGETS:
        raise ValueError("Too many targets (max 32)")
    targets = [scoped_ip(t, networks) for t in args.targets]
    ports = tuple(dict.fromkeys(args.ports))
    if not ports or len(ports) > MAX_PORTS or any(p < 1 or p > 65535 for p in ports):
        raise ValueError("Invalid port list (1-32 ports in range 1-65535)")
    output = {"tool": "NEXUS scoped active audit", "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), "scope": scope["allowed_cidrs"], "targets": []}
    for ip in targets:
        record = {"ip": str(ip), "ports": [], "checks": []}
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda p: check_port(ip, p, args.timeout), ports))
        record["ports"] = results
        open_ports = {p["port"] for p in results if p["state"] == "open"}
        for port in sorted(open_ports):
            if port in (443, 8443):
                record["checks"].append({"port": port, **tls_check(ip, port, args.timeout)})
                if args.verify_3des:
                    record["checks"].append(verify_3des(ip, port, args.timeout))
            if port in (80, 443, 8080, 8443):
                record["checks"].append({"port": port, "check": "http_headers", **web_checks(ip, port, args.timeout)})
            time.sleep(0.15)
        output["targets"].append(record)
        print(f"[+] {ip}: {len(open_ports)} open ports, {len(record['checks'])} checks")
    Path(args.output).write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"[+] Report written to {args.output}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scoped, non-destructive active checks on explicitly authorized IPs")
    parser.add_argument("--scope", required=True, help="JSON file containing allowed_cidrs")
    parser.add_argument("--targets", nargs="+", required=True, help="Literal IP addresses, no hostname expansion")
    parser.add_argument("--ports", nargs="+", type=int, default=list(DEFAULT_PORTS))
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--output", default="nexus-scan.json")
    parser.add_argument("--verify-3des", action="store_true", help="Non-destructive SWEET32/3DES TLS handshake check on 443/8443")
    args = parser.parse_args()
    if not 0.2 <= args.timeout <= 5:
        parser.error("--timeout must be between 0.2 and 5 seconds")
    try:
        run(args)
    except (ValueError, KeyError, OSError) as exc:
        parser.error(str(exc))
