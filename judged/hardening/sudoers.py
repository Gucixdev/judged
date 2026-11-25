"""sudo rules that need no password or no authentication. /etc/sudoers is root-only: as an ordinary user this answers `unknown`."""
import re

from ..controls import M_PRIVILEGES, Result

NAME, ORDER = "sudoers", 40


def rules(text: str) -> list:
    out, cur = [], ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#") and not line.startswith("#include"):
            continue
        cur += line.rstrip("\\")
        if line.endswith("\\"):
            continue
        if cur:
            out.append(cur)
        cur = ""
    return out


def check(cfg, env):
    try:
        names = [] if not _has(env, "/etc/sudoers.d") else [f"/etc/sudoers.d/{n}" for n in env.listdir("/etc/sudoers.d") if not n.endswith("~") and "." not in n]
        texts = {"/etc/sudoers": env.read("/etc/sudoers"), **{n: env.read(n) for n in names}}
    except PermissionError as e:
        return [Result("hardening.sudoers", "sudo rules", "unknown", f"cannot read {e.filename}: only root can; run judged as root to check", M_PRIVILEGES)]
    except FileNotFoundError:
        return [Result("hardening.sudoers", "sudo rules", "na", "no /etc/sudoers: sudo not installed", M_PRIVILEGES)]
    except OSError as e:
        return [Result("hardening.sudoers", "sudo rules", "unknown", f"cannot read sudoers: {e}", M_PRIVILEGES)]
    nopass, noauth = [], []
    for f, text in texts.items():
        for r in rules(text):
            if re.search(r"\bNOPASSWD\s*:", r):
                nopass.append(f"{f}: {r[:90]}")
            if re.match(r"Defaults.*!authenticate", r):
                noauth.append(f"{f}: {r[:90]}")
    bad = [f"no password asked: {x}" for x in nopass] + [f"authentication switched off: {x}" for x in noauth]
    accept = cfg.get("sudoers_accept", [])
    unaccepted = [b for b in bad if not any(a in b for a in accept)]
    return [Result("hardening.sudoers", "sudo rules", "warn" if unaccepted else "pass",
                   "; ".join(unaccepted[:6]) if unaccepted else f"{len(texts)} sudoers files read, no NOPASSWD or !authenticate" + (f" ({len(bad)} accepted)" if bad else ""), M_PRIVILEGES)]


def _has(env, path: str) -> bool:
    try:
        env.listdir(path)
        return True
    except FileNotFoundError:
        return False
