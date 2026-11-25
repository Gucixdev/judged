"""restic. NOT checked against a real restic (not installed here): `restic snapshots --json` is from its manual."""
import json
import os
from datetime import datetime, timezone

from . import Snapshot, Unreadable

NAME = "restic"


def latest(cfg, run, now):
    cmd = ["restic", "-r", cfg["repo"], "snapshots", "--json", "--no-lock"]
    if cfg.get("password_file"):
        cmd += ["--password-file", os.path.expanduser(cfg["password_file"])]
    rc, out = run(cmd, timeout=120)
    if rc is None:
        raise Unreadable("restic is not installed")
    if rc != 0:
        raise Unreadable(f"restic exit {rc}: wrong repository, password or no network")
    try:
        snaps = json.loads(out)
        newest = max(snaps, key=lambda s: s["time"])
    except (ValueError, KeyError, TypeError):
        raise Unreadable("restic answered, but not with a snapshot list") from None
    t = datetime.fromisoformat(newest["time"].replace("Z", "+00:00")).astimezone(timezone.utc)
    return Snapshot(t, list(newest.get("paths", [])), len(snaps), "snapshots")
