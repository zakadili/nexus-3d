"""Non-destructive CVE-2016-2183 / SWEET32 TLS 3DES configuration probe.

Detects whether a server negotiates a 3DES cipher with a TLS client.
Positive handshake = evidence of weak cipher support, NOT exploitation.
"""
import socket
import ssl

CVE = "CVE-2016-2183"

def verify_3des(ip, port, timeout=2.0):
    result = {"check": "cve_probe", "cve": CVE, "port": port, "status": "inconclusive"}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers("DES-CBC3-SHA:@SECLEVEL=0")
    except (ssl.SSLError, ValueError) as exc:
        result["reason"] = "Local OpenSSL does not support this probe: " + type(exc).__name__
        return result
    try:
        with socket.create_connection((str(ip), port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=None) as sock:
                cipher = sock.cipher()
                result["evidence"] = {"cipher": cipher[0] if cipher else None, "tls": sock.version()}
                if cipher and ("3DES" in cipher[0].upper() or "DES-CBC3" in cipher[0].upper()):
                    result["status"] = "weak_cipher_confirmed"
                    result["reason"] = "Server negotiated 3DES; this is configuration evidence, not exploit execution."
                else:
                    result["reason"] = "Negotiated cipher was not 3DES; result inconclusive."
    except (OSError, ssl.SSLError) as exc:
        result["reason"] = "Handshake did not succeed: " + type(exc).__name__ + ". This does not prove the server is unaffected."
    return result
