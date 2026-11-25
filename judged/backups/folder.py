"""A plain folder (rsync target, mounted disk): the newest file inside is the time of the last backup. It cannot say what the backup holds."""
import os
from datetime import datetime, timezone

from . import Snapshot, Unreadable

NAME = "folder"


def latest(cfg, run, now):
    repo = os.path.expanduser(cfg["repo"])
    if not os.path.isdir(repo):
        raise Unreadable(f"{repo} is not a folder (disk not mounted?)")
    newest, count, errors = 0.0, 0, 0
    for root, _, files in os.walk(repo, onerror=lambda e: None):
        for n in files:
            try:
                newest, count = max(newest, os.lstat(os.path.join(root, n)).st_mtime), count + 1
            except OSError:
                errors += 1
    if not count:
        raise Unreadable(f"{repo} holds no files")
    return Snapshot(datetime.fromtimestamp(newest, timezone.utc), None, count, "files")
