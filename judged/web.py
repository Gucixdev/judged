"""Websites, servers, domains: what an outsider can see. Only hosts you own or run; nothing here is intrusive
(one GET, one HEAD, DNS and RDAP lookups). Every check can say "unknown" instead of guessing."""
import http.client
import json
import re
import subprocess
import urllib.request
from datetime import datetime, timezone

from .controls import M_CONFIG, M_CRYPTO, Result

HEADERS = {   # header -> why it matters; absent = warn
    "content-security-policy": "CSP limits what injected script can do",
    "x-content-type-options": "nosniff stops MIME confusion",
    "referrer-policy": "limits what leaks in the Referer header",
    "permissions-policy": "turns off browser features the site does not use",
}


def fetch(host: str, scheme: str = "https", path: str = "/", method: str = "GET") -> tuple:
    c = (http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection)(host, timeout=10)
    try:
        c.request(method, path, headers={"User-Agent": "judged/0 compliance check"})
        r = c.getresponse()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, r.getheader("set-cookie"), r.read(200_000)
    finally:
        c.close()


def cookie_flags(raw_cookies: list) -> list:
    bad = []
    for c in raw_cookies:
        low = c.lower()
        miss = [f for f, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")) if k not in low]
        if miss:
            bad.append(f"{c.split('=')[0]} lacks {'/'.join(miss)}")
    return bad


def site(host: str, get=fetch) -> list:
    """Redirect to HTTPS, security headers, cookie flags, version-revealing Server header, security.txt."""
    rid, out = f"web.{host}", []
    try:
        st, hh, _, _ = get(host, "http", "/", "GET")
        loc = hh.get("location", "")
        ok = st in (301, 302, 307, 308) and loc.startswith("https://")
        out.append(Result(f"{rid}.redirect", f"{host} http to https", "pass" if ok else "warn",
                          f"HTTP {st} -> {loc or 'no redirect'}", M_CRYPTO))
    except OSError as e:
        out.append(Result(f"{rid}.redirect", f"{host} http to https", "unknown", f"port 80 not reachable: {e}", M_CRYPTO))
    try:
        st, h, _, body = get(host, "https", "/", "GET")
    except OSError as e:
        return out + [Result(f"{rid}.https", f"{host} https", "fail", f"cannot fetch: {e}", M_CRYPTO)]
    missing = [k for k in HEADERS if k not in h]
    if "content-security-policy" in h and "frame-ancestors" not in h["content-security-policy"] and "x-frame-options" not in h:
        missing.append("x-frame-options or CSP frame-ancestors")
    elif "content-security-policy" not in h and "x-frame-options" not in h and "x-frame-options or CSP frame-ancestors" not in missing:
        missing.append("x-frame-options")
    out.append(Result(f"{rid}.headers", f"{host} security headers", "warn" if missing else "pass",
                      ("missing: " + ", ".join(missing)) if missing else "all present", M_CONFIG))
    banner = h.get("server", "")
    if re.search(r"\d+\.\d+", banner) or "x-powered-by" in h:
        out.append(Result(f"{rid}.banner", f"{host} version disclosure", "warn",
                          f"Server/X-Powered-By reveals {banner or h.get('x-powered-by')}", M_CONFIG))
    try:
        cookies = _all_cookies(host)
    except OSError:
        cookies = []
    bad = cookie_flags(cookies)
    if cookies:
        out.append(Result(f"{rid}.cookies", f"{host} cookies", "warn" if bad else "pass",
                          "; ".join(bad) if bad else f"{len(cookies)} cookies, flags set", M_CONFIG))
    try:
        st, _, _, body = get(host, "https", "/.well-known/security.txt", "GET")
        exp = re.search(r"(?im)^expires:\s*(\S+)", body.decode("utf-8", "replace")) if st == 200 else None
        if st != 200:
            out.append(Result(f"{rid}.securitytxt", f"{host} security.txt", "warn", f"HTTP {st}: no /.well-known/security.txt (RFC 9116)", M_CONFIG))
        elif not exp:
            out.append(Result(f"{rid}.securitytxt", f"{host} security.txt", "warn", "present but no Expires field (required by RFC 9116)", M_CONFIG))
        else:
            dt = datetime.fromisoformat(exp.group(1).upper().replace("Z", "+00:00"))
            late = dt < datetime.now(timezone.utc)
            out.append(Result(f"{rid}.securitytxt", f"{host} security.txt", "warn" if late else "pass",
                              f"Expires {exp.group(1)}" + (" (past)" if late else ""), M_CONFIG))
    except (OSError, ValueError) as e:
        out.append(Result(f"{rid}.securitytxt", f"{host} security.txt", "unknown", str(e), M_CONFIG))
    return out


def _all_cookies(host: str) -> list:
    c = http.client.HTTPSConnection(host, timeout=10)
    try:
        c.request("GET", "/", headers={"User-Agent": "judged/0 compliance check"})
        return c.getresponse().msg.get_all("Set-Cookie") or []
    finally:
        c.close()


def dnssec(host: str, run=subprocess.run) -> Result:
    """A DS record at the parent means the zone is signed. Does not validate the chain; that is the resolver's job."""
    labels = host.split(".")
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        try:
            r = run(["dig", "+short", "DS", name], capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            return Result(f"web.{host}.dnssec", f"{host} DNSSEC", "unknown", "dig not available", M_CRYPTO)
        if r.returncode != 0:
            return Result(f"web.{host}.dnssec", f"{host} DNSSEC", "unknown", "DNS lookup failed (no resolver reachable)", M_CRYPTO)
        if r.stdout.strip():
            return Result(f"web.{host}.dnssec", f"{host} DNSSEC", "pass", f"DS record at the parent of {name}", M_CRYPTO)
    return Result(f"web.{host}.dnssec", f"{host} DNSSEC", "warn", "no DS record: zone is not signed (or the parent does not publish one)", M_CRYPTO)


def rdap_expiry(host: str, opener=urllib.request.urlopen) -> tuple:
    """(domain, expiry datetime) from RDAP (JSON, RFC 9083), trying the longest name first so co.uk-style suffixes work."""
    labels, last = host.split("."), None
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        try:
            with opener(urllib.request.Request(f"https://rdap.org/domain/{name}", headers={"Accept": "application/rdap+json"}), timeout=15) as r:
                data = json.load(r)
        except OSError as e:
            last = e
            continue
        for ev in data.get("events", []):
            if ev.get("eventAction") == "expiration":
                return name, datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
        return name, None
    if last is not None:
        raise last                      # nothing answered: say so, do not pretend the registry has no date
    return host, None
