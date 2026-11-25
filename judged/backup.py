"""Backup evidence results from judged/backups/ tools."""
import subprocess
from pathlib import Path
from datetime import date, datetime, timedelta, timezone

from . import backups
from .controls import Result

M_BACKUP = {"iso27001": ["A.8.13"], "gdpr": ["art32"]}


def _run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None, ""


def backup_check(cfg: dict, today: date, run=_run, now: datetime | None = None) -> list:
    now = now or datetime.now(timezone.utc)
    kinds = backups.tools()
    tool = cfg.get("tool", "")
    if not cfg.get("repo"):
        return [Result("backup.config", "Backup", "na", "no repo in the backup section: nothing checked", M_BACKUP)]
    if tool not in kinds:
        return [Result("backup.config", "Backup", "fail", f"unknown tool {tool!r} (known: {', '.join(sorted(kinds))})", M_BACKUP)]
    try:
        snap = kinds[tool].latest(cfg, run, now)
    except backups.Unreadable as e:
        return [Result("backup.latest", "Backup", "unknown", f"cannot read the {tool} repository: {e}; a backup nobody can read is not evidence", M_BACKUP)] + restore(cfg, today)
    age = now - snap.when
    limit = timedelta(hours=cfg.get("max_age_hours", 36))
    out = [Result("backup.latest", "Latest backup", "pass" if age <= limit else "fail",
                  f"{tool}: newest of {snap.count} {snap.unit if snap.count != 1 else snap.unit.rstrip('s')} is {backups.age_text(age)} old (limit {backups.age_text(limit)})"
                  if age >= timedelta(0) else f"{tool}: newest backup is dated in the future ({snap.when:%Y-%m-%d %H:%M}): clock wrong?", M_BACKUP)]
    if age < timedelta(0):
        out[0].status = "warn"
    wanted = cfg.get("must_include", [])
    if wanted:
        ok, missing = backups.covered(snap.paths, wanted)
        if snap.paths is None:
            out.append(Result("backup.coverage", "Backup coverage", "unknown", f"{tool} does not list what a backup holds: {', '.join(wanted)} not checked", M_BACKUP))
        else:
            out.append(Result("backup.coverage", "Backup coverage", "fail" if missing else "pass",
                              f"not in the newest backup: {', '.join(missing)}" if missing else f"all {len(wanted)} required folders are in the newest backup", M_BACKUP))
    return out + restore(cfg, today)


def stamp(path: str) -> tuple:
    """(text, problem): the first word of a stamp file, written by whatever ran the restore test."""
    try:
        words = Path(path).expanduser().read_text().split()
    except OSError as e:
        return "", f"stamp file {path} cannot be read: {e.strerror or e}"
    return (words[0], "") if words else ("", f"stamp file {path} is empty")


def restore(cfg: dict, today: date) -> list:
    """The newer of `restore_tested` (written by hand) and the stamp file (written by the tool that restored and compared a file)."""
    limit, found, bad, src = cfg.get("restore_max_age_days", 365), [], [], {}
    sources = [("restore_tested", cfg.get("restore_tested", ""), "")]
    if cfg.get("restore_tested_file"):
        sources.append(("restore_tested_file", *stamp(cfg["restore_tested_file"])))
    for name, text, problem in sources:
        if problem:
            bad.append(problem)
        elif text:
            try:
                found.append((date.fromisoformat(text), name))
            except ValueError:
                return [Result("backup.restore", "Restore test", "fail", f"{name} holds {text!r}, which is not a date (YYYY-MM-DD)", M_BACKUP)]
    if not found:
        return [Result("backup.restore", "Restore test", "warn", ("; ".join(bad) + "; " if bad else "") + "no restore test recorded: a backup that was never restored is a hope, not evidence. Restore one folder, then set restore_tested=YYYY-MM-DD or let a restore test write restore_tested_file", M_BACKUP)]
    d, name = max(found)
    days = (today - d).days
    if days < 0:
        return [Result("backup.restore", "Restore test", "warn", f"{name} {d} is in the future", M_BACKUP)]
    return [Result("backup.restore", "Restore test", "pass" if days <= limit else "warn", f"last restore test {days} days ago (limit {limit}), from {name}" + ("; " + "; ".join(bad) if bad else ""), M_BACKUP)]
