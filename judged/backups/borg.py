"""borg. NOT checked against a real borg (not installed here): `borg list --json` is from its manual. The passphrase must come from the
environment (BORG_PASSCOMMAND), judged never takes one. A list of archives does not say what each holds, so the folders are not checked."""
import json
from datetime import datetime, timezone

from . import Snapshot, Unreadable

NAME = "borg"


def latest(cfg, run, now):
    rc, out = run(["borg", "list", "--json", cfg["repo"]], timeout=120)
    if rc is None:
        raise Unreadable("borg is not installed")
    if rc != 0:
        raise Unreadable(f"borg exit {rc}: wrong repository, passphrase (BORG_PASSCOMMAND) or locked")
    try:
        arch = json.loads(out)["archives"]
        newest = max(arch, key=lambda a: a["start"])
    except (ValueError, KeyError, TypeError):
        raise Unreadable("borg answered, but not with an archive list") from None
    t = datetime.fromisoformat(newest["start"]).astimezone(timezone.utc)      # borg prints local time without a zone; a naive time is read as this machine's local time
    return Snapshot(t, None, len(arch), "archives")
