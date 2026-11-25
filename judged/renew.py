"""Certificate renewal supervisor. judged does NOT speak ACME: your client (certbot, lego, acme.sh, a script)
does. judged decides when, runs it, reloads the service, and then checks that the SERVED certificate really
changed, which is the step that fails silently in practice."""
import json
import subprocess
import time
from datetime import datetime, timezone

from . import net, renewers


def min_when_days(step_hours: float, retries: int, safety_days: float = 3.0) -> int:
    """Smallest whole `when_days` that survives `retries` failed attempts, each `step_hours` apart, and still has
    `safety_days` left for the next one. Proved safe and tight in lean4/Window.lean, held to AMPL in ampl/window.py."""
    import math
    return math.ceil(safety_days + retries * step_hours / 24 - 1e-9)


def window_warning(e: dict, every_hours: float, retries: int = 3, safety_days: float = 3.0) -> str | None:
    step = max(every_hours, e.get("min_interval_hours", 6))
    need = min_when_days(step, retries, safety_days)
    w = e.get("when_days", 21)
    if w < need:
        return (f"when_days={w:g} survives fewer than {retries} failed attempts ({step:g} h apart, keeping {safety_days:g} days "
                f"in reserve): use at least {need}")
    return None


def decide(days: float, when_days: float, last_attempt: float | None, now: float, min_interval_h: float) -> str:
    """ok: plenty of time | renew: due now | wait: due but tried too recently (ACME rate limits, restart storms)."""
    if days > when_days:
        return "ok"
    if last_attempt is not None and now - last_attempt < min_interval_h * 3600:
        return "wait"
    return "renew"


def served(e: dict) -> tuple:
    """(notAfter as epoch, days left, certificate lifetime in days) of what the service serves right now."""
    f = net.tls_facts(e["host"], e.get("port", 443), e.get("cafile"))
    ts = net.ssl.cert_time_to_seconds(f["cert"]["notAfter"])
    life = (ts - net.ssl.cert_time_to_seconds(f["cert"]["notBefore"])) / 86400
    return ts, (ts - time.time()) / 86400, life


def lifetime_hint(lifetime_days: float, when_days: float) -> str:
    """A certificate that lives no longer than `when_days` is inside the renewal window the moment it is issued:
    judged would renew it on every pass (6-day certificates exist). Say so instead of looping silently."""
    if lifetime_days <= when_days:
        return (f" WARNING: this certificate lives {lifetime_days:.0f} days but when_days={when_days:g}, so it is always due; "
                f"set when_days below {lifetime_days:.0f} (about a third of the lifetime)")
    return ""


def renew_one(e: dict, last_attempt: float | None, dry: bool, now: float | None = None, run=subprocess.run) -> tuple:
    """Returns (status, message, attempted). status: ok | wait | would-renew | renewed | failed."""
    now = now or time.time()
    other = renewers.find(e)
    if other:
        return other.renew_one(e, last_attempt, dry, now, run)
    try:
        before, days, life = served(e)
    except (OSError, ValueError, KeyError, net.ssl.SSLError) as ex:
        return "failed", f"cannot read the served certificate: {ex}", False
    d = decide(days, e.get("when_days", 21), last_attempt, now, e.get("min_interval_hours", 6))
    if d == "ok":
        return "ok", f"{days:.0f} days left", False
    hint = lifetime_hint(life, e.get("when_days", 21))
    if d == "wait":
        return "wait", f"{days:.0f} days left, last attempt too recent." + hint, False
    if dry:
        return "would-renew", f"{days:.0f} days left, would run: {' '.join(e['cmd'])}", False
    try:    # a missing program or a hung command is this host's failure, not the whole pass's
        r = run(e["cmd"], capture_output=True, text=True, timeout=e.get("timeout", 600))
    except (OSError, subprocess.TimeoutExpired) as ex:
        return "failed", f"renew command did not run to the end: {ex}", True
    if r.returncode != 0:
        return "failed", f"renew command exit {r.returncode}: {(r.stderr or r.stdout)[-200:].strip()}", True
    if e.get("reload"):
        try:
            r = run(e["reload"], capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired) as ex:
            return "failed", f"renewed but reload did not run to the end: {ex}", True
        if r.returncode != 0:
            return "failed", f"renewed but reload failed (exit {r.returncode}): {(r.stderr or r.stdout)[-200:].strip()}", True
    try:
        after, days2, life2 = served(e)
    except (OSError, ValueError, KeyError, net.ssl.SSLError) as ex:
        return "failed", f"renewed but the service no longer serves a valid certificate: {ex}", True
    if after <= before:
        return "failed", "command succeeded but the served certificate did not change (not deployed, reload missing?)", True
    return "renewed", (f"now {days2:.0f} days left, expires {datetime.fromtimestamp(after, timezone.utc):%Y-%m-%d}."
                       + lifetime_hint(life2, e.get("when_days", 21))), True
