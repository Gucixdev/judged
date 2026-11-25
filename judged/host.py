"""Host checks, read-only. Every check returns a Result; a missing tool or missing permission gives 'unknown',
never 'pass'. Services go through judged/inits/ (systemd, dinit, OpenRC, runit), package managers through judged/pkgmgrs/ (pacman, xbps, apt, dnf).
An init system or package manager without a file there answers 'unknown'."""
import glob
import json
import re
import subprocess
import time
from pathlib import Path

from . import inits, pkgmgrs
from .controls import M_CONFIG, M_HOST_FIREWALL, M_MALWARE, M_PASSWORD_LOGIN, M_PRIVILEGES, M_SERVICES, M_UPDATES, Result


def run(cmd: list, timeout: int = 20) -> tuple:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None, ""


def service(units, title: str, ident: str, maps: dict, none_up: str) -> Result:
    """Is one of these services up, on whatever init system this machine has. Cannot ask => unknown, never warn or pass."""
    state, which, init = inits.active(units, run)
    if state:
        return Result(ident, title, "pass", f"{which} is active ({init})", maps)
    if state is None:
        return Result(ident, title, "unknown", f"cannot ask the init system ({init}): not supported here or not reachable", maps)
    return Result(ident, title, "warn", f"{none_up} ({init})", maps)


def firewall() -> Result:
    return service(("ufw", "firewalld", "nftables", "iptables"), "Host firewall", "host.firewall", M_HOST_FIREWALL,
                   "no ufw/firewalld/nftables service active (a ruleset loaded another way is not detected; needs root to list)")


def parse_sshd(text: str, read=lambda p: Path(p).read_text()) -> dict:
    """First value wins, as in sshd. `Include` is expanded where it stands."""
    conf: dict = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        k, _, v = line.partition(" ")
        if k.lower() == "match":
            break                                           # the rest applies to some connections only, never read as a global setting
        if k.lower() == "include":
            for p in sorted(glob.glob(v.strip() if v.startswith("/") else "/etc/ssh/" + v.strip())):
                for kk, vv in parse_sshd(read(p), read).items():
                    conf.setdefault(kk, vv)
        else:
            conf.setdefault(k.lower(), v.strip().lower())
    return conf


def ssh() -> Result:
    p = Path("/etc/ssh/sshd_config")
    if not p.exists():
        return Result("host.ssh", "SSH server", "na", "no sshd_config: no SSH server installed", M_PASSWORD_LOGIN)
    try:
        c = parse_sshd(p.read_text())
    except OSError as e:
        return Result("host.ssh", "SSH server", "unknown", f"cannot read sshd_config: {e}", M_PASSWORD_LOGIN)
    root, pw = c.get("permitrootlogin", "prohibit-password"), c.get("passwordauthentication", "yes")
    bad = []
    if root == "yes":
        bad.append("root login with password allowed")
    if pw == "yes":
        bad.append("password authentication on")
    return Result("host.ssh", "SSH server", "warn" if bad else "pass",
                  "; ".join(bad) or f"PermitRootLogin={root}, PasswordAuthentication={pw}", M_PASSWORD_LOGIN)


def root_encrypted(tree: dict, under_crypt: bool = False) -> bool | None:
    """lsblk -J tree: is the node mounted at / inside a crypt device? None if no node mounted at /."""
    crypt = under_crypt or tree.get("type") == "crypt"
    mps = tree.get("mountpoints") or []
    if "/" in mps:
        return crypt
    for ch in tree.get("children") or []:
        r = root_encrypted(ch, crypt)
        if r is not None:
            return r
    return None


def disk_encryption() -> Result:
    rc, out = run(["lsblk", "-J", "-o", "NAME,TYPE,MOUNTPOINTS"])
    if rc != 0:
        return Result("host.disk", "Disk encryption", "unknown", "lsblk not available", M_CONFIG)
    res = [root_encrypted(d) for d in json.loads(out).get("blockdevices", [])]
    res = [r for r in res if r is not None]
    if not res:
        return Result("host.disk", "Disk encryption", "unknown", "no device mounted at / found", M_CONFIG)
    return Result("host.disk", "Disk encryption", "pass" if res[0] else "fail",
                  "root is inside a crypt device" if res[0] else "root filesystem is not on an encrypted device", M_CONFIG)


def updates() -> Result:
    pm = pkgmgrs.current()
    if pm is None:
        return Result("host.updates", "Pending updates", "unknown", "no supported package manager (known: " + ", ".join(sorted(m.NAME for m in pkgmgrs.discover())) + ")", M_UPDATES)
    n = pm.pending(run)
    if n is None:
        return Result("host.updates", "Pending updates", "unknown", f"{pm.NAME} did not answer", M_UPDATES)
    dbs = [d for g in getattr(pm, "DB_GLOBS", []) for d in glob.glob(g)]
    age = (time.time() - max(Path(d).stat().st_mtime for d in dbs)) / 86400 if dbs else None
    stale = age is not None and age > 7
    st = "warn" if stale or n else "pass"
    return Result("host.updates", "Pending updates", st,
                  f"{n} pending ({pm.NAME})" + (f"; package lists synced {age:.0f} days ago" if age is not None else "; age of the package lists unknown")
                  + (" (stale: the count may be low)" if stale else ""), M_UPDATES)


def listening(accept: tuple = ()) -> Result:
    rc, out = run(["ss", "-H", "-tln"])
    if rc != 0:
        return Result("host.ports", "Listening services", "unknown", "ss not available", M_SERVICES)
    exposed = []
    for l in out.splitlines():
        f = l.split()
        if len(f) >= 4 and not re.match(r"^(127\.|\[::1\]|::1)", f[3]) and f[3].rsplit(":", 1)[-1] not in accept:
            exposed.append(f[3])
    return Result("host.ports", "Listening services", "warn" if exposed else "pass",
                  ("reachable beyond loopback: " + ", ".join(sorted(set(exposed))[:10])) if exposed
                  else "only loopback" + (f" and accepted ports {', '.join(accept)}" if accept else ""), M_SERVICES)


def extra_uid0() -> Result:
    users = [l.split(":")[0] for l in Path("/etc/passwd").read_text().splitlines()
             if l.count(":") >= 3 and l.split(":")[2] == "0" and not l.startswith("root:")]
    return Result("host.uid0", "Accounts with uid 0", "fail" if users else "pass",
                  ("extra root-equivalent accounts: " + ", ".join(users)) if users else "only root", M_PRIVILEGES)


def malware() -> Result:
    return service(("clamav-daemon", "clamd@scan", "clamd", "clamav-freshclam", "freshclamd"), "Anti-malware", "host.malware", M_MALWARE,
                   "no ClamAV service active (other products are not detected)")


def guarded(ident: str, title: str, maps: dict, check) -> Result:
    try:
        return check()
    except Exception as e:                                  # noqa: BLE001 - one broken check must not take the others with it
        return Result(ident, title, "unknown", f"the check crashed ({type(e).__name__}: {e})", maps)


def all_checks(accept_ports: tuple = ()) -> list:
    return [guarded(*row) for row in (
        ("host.firewall", "Host firewall", M_HOST_FIREWALL, firewall),
        ("host.ports", "Listening services", M_SERVICES, lambda: listening(tuple(accept_ports))),
        ("host.ssh", "SSH server", M_PASSWORD_LOGIN, ssh),
        ("host.disk", "Disk encryption", M_CONFIG, disk_encryption),
        ("host.updates", "Pending updates", M_UPDATES, updates),
        ("host.uid0", "Accounts with uid 0", M_PRIVILEGES, extra_uid0),
        ("host.malware", "Anti-malware", M_MALWARE, malware))]
