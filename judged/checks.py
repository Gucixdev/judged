"""Collectors: each returns Items with a real expiry date."""
import socket
import ssl
import subprocess
from datetime import datetime, timezone


def tls(name: str, host: str, port: int = 443) -> list:
    from .core import Item
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as s, ctx.wrap_socket(s, server_hostname=host) as t:
        ts = ssl.cert_time_to_seconds(t.getpeercert()["notAfter"])
    return [Item("tls", name, datetime.fromtimestamp(ts, timezone.utc))]


def parse_gpg(colons: str) -> list:
    """Parse `gpg --list-keys --with-colons`: pub/sub records carry the expiry epoch in field 7.
    Keys without an expiry are skipped; the label is the short key id, not the user id."""
    from .core import Item
    out, last = [], None
    for line in colons.splitlines():
        f = line.split(":")
        if f[0] in ("pub", "sub"):
            last = (f[0], f[4][-8:], f[6] if len(f) > 6 else "")
            if last[2]:
                out.append(Item("gpg", f"{last[0]} {last[1]}", datetime.fromtimestamp(int(last[2]), timezone.utc)))
    return out


def gpg(gnupghome: str | None = None) -> list:
    cmd = ["gpg", "--list-keys", "--with-colons"]
    if gnupghome:
        cmd[1:1] = ["--homedir", gnupghome]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return parse_gpg(r.stdout) if r.returncode == 0 else []


def date(name: str, expires, kind: str = "date", meta: dict | None = None) -> list:
    from .core import Item
    if isinstance(expires, datetime):
        dt = expires if expires.tzinfo else expires.replace(tzinfo=timezone.utc)
    else:  # toml date
        dt = datetime(expires.year, expires.month, expires.day, tzinfo=timezone.utc)
    return [Item(kind, name, dt, meta or {})]


def domain(host: str) -> list:
    """Registration expiry of the domain (RDAP). Losing a domain loses the site, the mail and the certificates."""
    from . import web
    from .core import Item
    name, exp = web.rdap_expiry(host)
    if exp is None:
        raise ValueError(f"no expiry date from RDAP for {host} (registry may not publish one)")
    return [Item("domain", name, exp)]
