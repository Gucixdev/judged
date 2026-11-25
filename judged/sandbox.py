"""Flatpak sandbox audit: what each installed app is allowed to do outside its sandbox.

Reads `flatpak list`, `flatpak info --show-permissions APP` and the user/system overrides (global and per app,
merged in that order, an override beats the app's own metadata). Token meanings are from flatpak-metadata(5).
The fail/warn thresholds are our judgement, not a standard; `accept` in the config marks a finding as a known,
accepted risk (it stays visible in the evidence, it just stops counting)."""
import configparser
import os
import subprocess
from pathlib import Path

from .controls import M_CONFIG, M_UNUSED, M_UPDATES, Result

# findings: key -> (severity, text)
SENSITIVE_PATHS = (".ssh", ".gnupg", ".aws", ".kube", ".password-store", ".config/gcloud", ".docker")
ESCAPE_NAMES = {"org.freedesktop.Flatpak": "can start any command on the host",
                "org.freedesktop.systemd1": "can start any command on the host through systemd"}


def parse_keyfile(text: str) -> dict:
    cp = configparser.ConfigParser(interpolation=None, strict=False, delimiters=("=",), allow_no_value=True)
    cp.optionxform = str
    try:
        cp.read_string(text)
    except configparser.Error:
        return {}
    return {s: dict(cp.items(s)) for s in cp.sections()}


def tokens(value: str | None) -> list:
    """`a;!b;if:x:!y;` -> ['a', '!b']. Conditional entries (if:...) are dropped: they are not unconditional grants."""
    return [t for t in (value or "").split(";") if t and not t.startswith("if:")]


def _fs_name(tok: str) -> str:
    return tok.rsplit(":", 1)[0] if tok.rsplit(":", 1)[-1] in ("ro", "rw", "create") else tok


def merge(layers: list) -> dict:
    """Apply permission layers in order. Lists: plain adds, `!x` removes x (any mode). Bus policy: name=none removes."""
    out = {"shared": [], "sockets": [], "devices": [], "features": [], "filesystems": [], "session": {}, "system": {},
           "from_global": set()}
    for layer in layers:
        ctx = layer.get("Context", {})
        for key in ("shared", "sockets", "devices", "features", "filesystems"):
            for t in tokens(ctx.get(key)):
                if t.startswith("!"):
                    gone = t[1:]
                    out[key] = [x for x in out[key] if (_fs_name(x) if key == "filesystems" else x) != _fs_name(gone)]
                else:
                    if key == "filesystems":
                        out[key] = [x for x in out[key] if _fs_name(x) != _fs_name(t)]
                    if t not in out[key]:
                        out[key].append(t)
        for sec, dst in (("Session Bus Policy", "session"), ("System Bus Policy", "system")):
            for name, level in layer.get(sec, {}).items():
                if level in (None, "none"):
                    out[dst].pop(name, None)
                else:
                    out[dst][name] = level
    return out


def findings(p: dict) -> list:
    """[(key, severity, text)] for a merged permission set."""
    out = []
    s = p["sockets"]
    if "session-bus" in s:
        out.append(("socket:session-bus", "fail", "full D-Bus session bus (can ask the host to run commands)"))
    if "system-bus" in s:
        out.append(("socket:system-bus", "warn", "full D-Bus system bus"))
    if "ssh-auth" in s:
        out.append(("socket:ssh-auth", "warn", "can use your ssh-agent keys"))
    if "gpg-agent" in s:
        out.append(("socket:gpg-agent", "warn", "can use your gpg-agent"))
    if "x11" in s and "wayland" not in s:
        out.append(("socket:x11-only", "warn", "X11 only: X11 clients can read each other's keystrokes and windows"))
    if "all" in p["devices"]:
        out.append(("dev:all", "warn", "all device nodes in /dev"))
    if "devel" in p["features"]:
        out.append(("feature:devel", "warn", "ptrace-class system calls allowed (features=devel)"))
    for t in p["filesystems"]:
        name, mode = _fs_name(t), (t.rsplit(":", 1)[-1] if t != _fs_name(t) else "rw")
        base = name.rstrip("/") or "/"
        if base in ("host", "host-os", "host-etc", "/"):
            out.append((f"fs:{base}", "fail" if mode != "ro" else "warn", f"whole host file system ({mode})"))
        elif base in ("xdg-config", "xdg-data"):
            out.append((f"fs:{base}", "warn", f"the whole {base} directory ({mode}): other apps' settings and tokens"))
        elif base in ("home", "~"):
            out.append(("fs:home", "fail" if mode != "ro" else "warn", f"the whole home directory ({mode}), which holds your keys and tokens"))
        else:
            for sp in SENSITIVE_PATHS:
                if base.endswith(sp) or f"{sp}/" in base:
                    out.append((f"fs:{sp}", "fail", f"{base} ({mode}) holds credentials"))
    for name, why in ESCAPE_NAMES.items():
        if p["session"].get(name) in ("talk", "own"):
            out.append((f"bus:{name}", "fail", f"talks to {name}: {why}"))
    if p["session"].get("org.freedesktop.secrets") in ("talk", "own"):
        out.append(("bus:org.freedesktop.secrets", "warn", "can read the keyring (org.freedesktop.secrets)"))
    return out


def _run(cmd: list, run=subprocess.run):
    try:
        r = run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else None


def permissions(app: str, install: str, run=subprocess.run) -> dict | None:
    meta = _run(["flatpak", "info", "--show-permissions", app], run)
    if meta is None:
        return None
    layers = [parse_keyfile(meta)]
    scope = "--user" if install == "user" else "--system"
    glob = None
    for target in ([], [app]):          # global override first, then the app's own
        ov = _run(["flatpak", "override", scope, "--show", *target], run)
        if ov:
            layers.append(parse_keyfile(ov))
            if not target:
                glob = layers[-1]
    merged = merge(layers)
    # findings that the global override alone already grants: the app is not the cause, the override is
    merged["from_global"] = {k for k, _, _ in findings(merge([glob]))} if glob else set()
    return merged


def flatpak_check(accept: list | None = None, ignore: list | None = None, run=subprocess.run) -> list:
    """One result per installed app, plus remotes and pending updates."""
    out = _run(["flatpak", "list", "--app", "--columns=application,installation"], run)
    if out is None:
        return [Result("flatpak", "Flatpak", "na", "flatpak is not installed or did not answer", M_CONFIG)]
    accepted = {}
    for a in accept or []:
        app, _, key = a.partition("=")
        accepted.setdefault(app, set()).add(key)
    results = []
    for line in out.strip().splitlines():
        app, _, install = line.partition("\t")
        app, install = app.strip(), install.strip() or "system"
        if not app or app in (ignore or []):
            continue
        p = permissions(app, install, run)
        rid, title = f"flatpak.{app}", f"Flatpak {app} sandbox"
        if p is None:
            results.append(Result(rid, title, "unknown", "could not read its permissions", M_CONFIG))
            continue
        live, shown = [], []
        for key, sev, text in findings(p):
            if key in p.get("from_global", ()):
                text += " [granted to every app by your global override]"
            if key in accepted.get(app, ()) or key in accepted.get("*", ()):
                shown.append(f"accepted: {text}")
            else:
                live.append((sev, text))
                shown.append(f"{sev}: {text}")
        status = "fail" if any(s == "fail" for s, _ in live) else "warn" if live else "pass"
        results.append(Result(rid, title, status, "; ".join(shown) or "no wide permissions", M_CONFIG))
    remotes = _run(["flatpak", "remotes", "--columns=name,options"], run)
    if remotes is not None:
        bad = [ln.split("\t")[0] for ln in remotes.splitlines() if "no-gpg-verify" in ln]
        results.append(Result("flatpak.remotes", "Flatpak remotes verify signatures", "fail" if bad else "pass",
                              ("signature check off for: " + ", ".join(sorted(set(bad)))) if bad else "every remote verifies signatures", M_CONFIG))
    upd = _run(["flatpak", "remote-ls", "--updates", "--columns=application"], run)
    if upd is None:
        results.append(Result("flatpak.updates", "Flatpak updates", "unknown", "could not ask the remote (offline?)", M_UPDATES))
    else:
        n = len([x for x in upd.splitlines() if x.strip()])
        results.append(Result("flatpak.updates", "Flatpak updates", "warn" if n else "pass",
                              f"{n} update(s) waiting" if n else "up to date", M_UPDATES))
    return results


def _du_mb(path: Path, run=subprocess.run) -> float | None:
    out = _run(["du", "-sk", str(path)], run)
    try:
        return int(out.split()[0]) / 1024 if out else None
    except (ValueError, IndexError):
        return None


def _mb(text: str) -> float:
    """'1.1 GB' / '17.3 MB' / '163.8 kB' as MB; unreadable -> 0."""
    try:
        n, unit = text.replace("\xa0", " ").split()[:2]
        return float(n) * {"bytes": 1e-6, "kB": 1e-3, "MB": 1.0, "GB": 1e3}.get(unit, 0.0)
    except (ValueError, IndexError):
        return 0.0


def flatpak_leftovers(var_app: Path | None = None, run=subprocess.run) -> list:
    """Read only. Data of apps that are no longer installed, and base runtimes no installed app uses.
    Never deletes: it names the leftovers and the command that would."""
    apps_out = _run(["flatpak", "list", "--app", "--columns=application,runtime"], run)
    if apps_out is None:
        return []
    rows = [ln.split("\t") for ln in apps_out.splitlines() if ln.strip()]
    installed = {r[0].strip() for r in rows}
    used = {tuple(r[1].strip().split("/")[::2]) for r in rows if len(r) > 1 and r[1].count("/") == 2}     # (runtime id, branch)
    out = []
    root = (var_app or Path.home() / ".var" / "app")
    try:
        # the folder may be a symlink onto the Flatpak install dir (app, repo, runtime ...): only reverse-DNS names are app data
        names = sorted(n for n in os.listdir(root) if "." in n.strip(".") and not n.startswith(".") and n not in installed)
    except OSError:
        names = None
    if names is None:
        out.append(Result("flatpak.leftover-data", "Flatpak data of removed apps", "unknown", f"cannot read {root}", M_CONFIG))
    elif names:
        sized = [(n, _du_mb(root / n, run)) for n in names]
        total = sum(s or 0 for _, s in sized)
        out.append(Result("flatpak.leftover-data", "Flatpak data of removed apps", "warn",
                          f"{len(names)} folders of apps that are not installed ({total:.0f} MB, may hold personal data): "
                          + ", ".join(f"{n} ({s:.0f} MB)" if s is not None else n for n, s in sized)
                          + f". Look in {root} and move or delete them yourself", M_CONFIG))
    else:
        out.append(Result("flatpak.leftover-data", "Flatpak data of removed apps", "pass", "no data folder of a removed app", M_CONFIG))
    rt = _run(["flatpak", "list", "--runtime", "--columns=application,branch,size"], run)
    if rt is None:
        out.append(Result("flatpak.runtimes", "Flatpak unused runtimes", "unknown", "could not list runtimes", M_UNUSED))
        return out
    bases = {r[0] for r in used}
    stale = []
    for ln in rt.splitlines():
        cols = ln.split("\t")
        if len(cols) >= 2 and cols[0].endswith(".Platform") and cols[0] in bases and (cols[0], cols[1]) not in used:
            stale.append((cols[0], cols[1], _mb(cols[2]) if len(cols) > 2 else 0.0))
    if stale:
        out.append(Result("flatpak.runtimes", "Flatpak unused runtimes", "warn",
                          f"{len(stale)} runtime version{'' if len(stale) == 1 else 's'} that no installed app uses directly ({sum(s for *_, s in stale) / 1000:.1f} GB): "
                          + ", ".join(f"{a}//{b}" for a, b, _ in stale)
                          + ". Candidates only (another runtime may still need one): `flatpak remove --unused` lists what Flatpak itself would remove", M_UNUSED))
    else:
        out.append(Result("flatpak.runtimes", "Flatpak unused runtimes", "pass", "every base runtime version is used by an installed app", M_UNUSED))
    return out
