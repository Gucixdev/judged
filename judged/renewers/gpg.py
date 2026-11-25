"""GPG key expiry extension: `renew gpg:FINGERPRINT when_days=30 extend_by=2y [homedir=...]`.

Only keys named by fingerprint in the config are touched, the primary key and all its subkeys get the new date (two gpg calls: `*` alone leaves the primary key unchanged), and judged then reads the
key back to check that the date really moved. judged never sees or stores a passphrase: gpg-agent asks for it (a key whose agent cannot ask
in the background fails here, and the failure is reported). Publishing the longer-lived key (keyserver, WKD, your site) is NOT done: judged
says so in the message."""
import re
import subprocess
import time
from datetime import datetime, timezone

from ..renew import decide

NAME = "gpg"
FPR = re.compile(r"^[0-9A-Fa-f]{40}$|^[0-9A-Fa-f]{64}$")
SPAN = re.compile(r"^\d+[dwmy]$|^\d{8}T\d{6}$|^\d{4}-\d{2}-\d{2}$")


def handles(e: dict) -> bool:
    return str(e.get("host", "")).startswith("gpg:")


def _base(e):
    return ["gpg", "--batch"] + (["--homedir", e["homedir"]] if e.get("homedir") else [])


def expiry(e, run) -> tuple:
    """(epoch or None for 'never expires', state letter) of the primary key; raises LookupError when gpg cannot show the key."""
    r = run(_base(e) + ["--list-keys", "--with-colons", "--fixed-list-mode", e["host"][4:]], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise LookupError((r.stderr or "gpg could not list the key").strip().splitlines()[-1][:120])
    for line in r.stdout.splitlines():
        f = line.split(":")
        if f[0] == "pub" and len(f) > 6:
            return (int(f[6]) if f[6] else None), f[1]
    raise LookupError("gpg listed no primary key for that fingerprint")


def renew_one(e: dict, last_attempt, dry: bool, now: float | None = None, run=subprocess.run) -> tuple:
    now = now or time.time()
    fpr, span = e["host"][4:], e.get("extend_by", "2y")
    if not FPR.match(fpr):
        return "failed", f"{fpr!r} is not a full fingerprint (40 or 64 hex digits): a short id could match another key", False
    if not SPAN.match(span):
        return "failed", f"extend_by={span!r} is not like 2y, 6m, 30d or a date YYYY-MM-DD", False
    try:
        before, state = expiry(e, run)
    except (OSError, subprocess.TimeoutExpired, LookupError, ValueError) as ex:
        return "failed", f"cannot read the key: {ex}", False
    if state == "r":
        return "failed", "this key is revoked: a revoked key must not be extended", False
    if before is None:
        return "ok", "the key has no expiry date, nothing to extend", False
    days = (before - now) / 86400
    d = decide(days, e.get("when_days", 30), last_attempt, now, e.get("min_interval_hours", 6))
    if d == "ok":
        return "ok", f"{days:.0f} days left", False
    if d == "wait":
        return "wait", f"{days:.0f} days left, last attempt too recent", False
    if dry:
        return "would-renew", f"{days:.0f} days left, would run: gpg --quick-set-expire <fingerprint> {span}, then the same for all subkeys", False
    for what, extra in (("the primary key", []), ("the subkeys", ["*"])):      # gpg: without a subkey argument only the primary key changes, "*" is subkeys only
        try:
            r = run(_base(e) + ["--yes", "--quick-set-expire", fpr, span] + extra, capture_output=True, text=True, timeout=e.get("timeout", 120))
        except (OSError, subprocess.TimeoutExpired) as ex:
            return "failed", f"gpg did not run to the end for {what}: {ex} (is the passphrase prompt waiting somewhere?)", True
        if r.returncode != 0:
            return "failed", f"gpg exit {r.returncode} for {what}: {(r.stderr or r.stdout)[-200:].strip()}", True
    try:
        after, _ = expiry(e, run)
    except (OSError, subprocess.TimeoutExpired, LookupError, ValueError) as ex:
        return "failed", f"extended, but the key cannot be read back: {ex}", True
    if after is None or after <= before:
        return "failed", "gpg said ok but the expiry date did not move", True
    return "renewed", (f"now expires {datetime.fromtimestamp(after, timezone.utc):%Y-%m-%d} ({(after - now) / 86400:.0f} days). "
                       "The longer-lived key is only in your keyring: publish it again (keyserver, WKD, your site), judged does not upload"), True
