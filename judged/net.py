"""Network and key checks: TLS posture and ACME hygiene of a host, GPG key strength."""
import http.client
import socket
import ssl
import subprocess
from datetime import datetime, timezone

from .controls import M_CRYPTO, Result


def tls_facts(host: str, port: int = 443, cafile: str | None = None) -> dict:
    ctx = ssl.create_default_context(cafile=cafile)  # cafile: a private/corporate CA instead of the system store
    with socket.create_connection((host, port), timeout=10) as s, ctx.wrap_socket(s, server_hostname=host) as t:
        cert = t.getpeercert()
        return {"version": t.version(), "cert": cert}


def hsts(host: str, port: int = 443) -> str | None:
    c = http.client.HTTPSConnection(host, port, timeout=10)
    try:
        c.request("HEAD", "/")
        return c.getresponse().getheader("strict-transport-security")
    finally:
        c.close()


def caa(host: str) -> str | None:
    """CAA names the CAs allowed to issue for the domain (what ACME clients check). Climbs the labels."""
    labels = host.split(".")
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        try:
            r = subprocess.run(["dig", "+short", "CAA", name], capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if r.returncode != 0:
            return None
        if r.stdout.strip():
            return r.stdout.strip().replace("\n", "; ")
    return ""


def issuer_org(cert: dict) -> str:
    for rdn in cert.get("issuer", ()):
        for k, v in rdn:
            if k == "organizationName":
                return v
    return "unknown"


def evaluate_tls(host: str, facts: dict, hsts_header: str | None, caa_val: str | None, now: datetime) -> list:
    cert = facts["cert"]
    na = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
    nb = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc)
    left, life = (na - now).days, (na - nb).days
    v = facts["version"]
    out = [
        Result(f"tls.{host}.version", f"{host} protocol", "pass" if v in ("TLSv1.3", "TLSv1.2") else "fail",
               f"negotiated {v}", M_CRYPTO),
        Result(f"tls.{host}.expiry", f"{host} certificate", "fail" if left < 0 else "warn" if left < 14 else "pass",
               f"{left} days left, issued by {issuer_org(cert)}", M_CRYPTO),
        Result(f"tls.{host}.acme", f"{host} issuance", "pass" if life <= 100 else "warn",
               f"lifetime {life} days" + (" (short-lived: usually automated renewal; not proof of ACME)" if life <= 100
                                          else " (long-lived: renewal is probably manual, an expiry risk)"), M_CRYPTO),
        Result(f"tls.{host}.hsts", f"{host} HSTS", "pass" if hsts_header else "warn",
               hsts_header or "no Strict-Transport-Security header", M_CRYPTO),
    ]
    out.append(Result(f"tls.{host}.caa", f"{host} CAA", "unknown" if caa_val is None else "pass" if caa_val else "warn",
                      "DNS lookup failed (dig missing or no resolver reachable)" if caa_val is None else caa_val or "no CAA record: any CA may issue", M_CRYPTO))
    return out


def tls(host: str, now: datetime | None = None, port: int = 443) -> list:
    now = now or datetime.now(timezone.utc)
    try:
        facts = tls_facts(host, port)
    except (OSError, ssl.SSLError) as e:
        return [Result(f"tls.{host}.connect", f"{host} TLS", "fail", f"cannot establish verified TLS: {e}", M_CRYPTO)]
    try:
        h = hsts(host, port)
    except OSError:
        h = None
    return evaluate_tls(host, facts, h, caa(host), now)


ALGO = {1: "RSA", 16: "ElGamal", 17: "DSA", 18: "ECDH", 19: "ECDSA", 22: "EdDSA"}


def gpg_hygiene(colons: str) -> list:
    """From `gpg --list-keys --with-colons`: fail on weak or broken, warn on a short RSA key or no expiry.
    Labels are short key ids, never user ids."""
    out = []
    for line in colons.splitlines():
        f = line.split(":")
        if f[0] not in ("pub", "sub") or len(f) < 7:
            continue
        kid, bits, algo = f[4][-8:], int(f[2] or 0), ALGO.get(int(f[3] or 0), f"algo {f[3]}")
        if f[1] in ("e", "r"):
            st, why = "fail", "expired" if f[1] == "e" else "revoked"
        elif algo in ("DSA", "ElGamal") or (algo == "RSA" and bits < 2048):
            st, why = "fail", f"{algo} {bits} is weak"
        elif algo == "RSA" and bits < 3072:
            st, why = "warn", f"RSA {bits}: below the 3072 bits recommended for new keys"
        elif not f[6]:
            st, why = "warn", f"{algo} {bits}, no expiry set"
        else:
            st, why = "pass", f"{algo} {bits}, expiry set"
        out.append(Result(f"gpg.{kid}", f"GPG {f[0]} {kid}", st, why, M_CRYPTO))
    return out


def gpg() -> list:
    try:
        r = subprocess.run(["gpg", "--list-keys", "--with-colons"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return [Result("gpg", "GPG keys", "unknown", "gpg not available", M_CRYPTO)]
    return gpg_hygiene(r.stdout) if r.returncode == 0 else []
