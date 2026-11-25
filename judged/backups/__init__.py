"""Backup evidence: is there a recent backup, does it cover the folders that matter, was a restore ever tried (ISO 27001 A.8.13).
One file per backup tool, found automatically:

    NAME = "restic"
    def latest(cfg, run, now) -> Snapshot          # raises Unreadable("why") when the repository cannot be asked
Snapshot(when: datetime (UTC), paths: list | None, count: int, unit); paths None = this tool cannot say what a backup holds.
A new tool is a new file. judged never writes to a repository and never reads backup contents; it asks for the list of snapshots only."""
import importlib
import pkgutil
from dataclasses import dataclass
from datetime import datetime, timedelta


class Unreadable(Exception):
    pass


@dataclass
class Snapshot:
    when: datetime
    paths: list | None
    count: int
    unit: str = "snapshots"                         # what `count` counts: snapshots, archives, files


def tools() -> dict:
    mods = [importlib.import_module(f"{__name__}.{m.name}") for m in pkgutil.iter_modules(__path__)]
    return {m.NAME: m for m in mods if hasattr(m, "latest")}


def covered(paths: list | None, wanted: list) -> tuple:
    """(covered, missing). A wanted folder is covered when a backed-up path is it or a parent of it."""
    if paths is None:
        return [], list(wanted)
    norm = [p.rstrip("/") or "/" for p in paths]
    ok = [w for w in wanted if any(w.rstrip("/") == p or w.startswith(p.rstrip("/") + "/") or p == "/" for p in norm)]
    return ok, [w for w in wanted if w not in ok]


def age_text(delta: timedelta) -> str:
    h = delta.total_seconds() / 3600
    return f"{h:.0f} hours" if h < 48 else f"{h / 24:.0f} days"
