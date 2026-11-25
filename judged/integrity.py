"""File integrity baseline: a manifest (path, size, mode, SHA-256) of chosen folders, then a report of what was added, changed or removed since.
The baseline is made only on request (`judged integrity init`) and replaced only on request (`judged integrity accept`), never as a side effect
of an audit: otherwise the first run after a break-in would bless the break-in. Symlinks are recorded by their target, never followed."""
import fnmatch
import hashlib
import json
import os
import stat
from pathlib import Path

from .controls import M_CONFIG, Result

M_INTEGRITY = {"iso27001": ["A.8.9", "A.8.16"], "gdpr": ["art32"]}


def scan(paths, exclude=(), max_filesize_mb=100, max_files=200000) -> tuple:
    """(manifest, problems). manifest = {absolute path: {"type", "size", "mode", "sha256" | "target"}}."""
    files, problems, limit = {}, [], max_filesize_mb * 1024 * 1024

    def skipped(p):
        return any(fnmatch.fnmatch(p, g) or fnmatch.fnmatch(os.path.basename(p), g) for g in exclude)

    for top in paths:
        top = os.path.abspath(os.path.expanduser(top))
        if not os.path.isdir(top):
            problems.append(f"{top}: not a folder")
            continue
        for root, dirs, names in os.walk(top, onerror=lambda e: problems.append(f"{e.filename}: {e.strerror}")):
            dirs[:] = sorted(d for d in dirs if not skipped(os.path.join(root, d)))
            for n in sorted(names):
                p = os.path.join(root, n)
                if skipped(p):
                    continue
                if len(files) >= max_files:
                    problems.append(f"stopped at {max_files} files: raise max_files, the rest is not covered")
                    return files, problems
                try:
                    st = os.lstat(p)
                    if stat.S_ISLNK(st.st_mode):
                        files[p] = {"type": "link", "target": os.readlink(p), "mode": stat.S_IMODE(st.st_mode)}
                    elif stat.S_ISREG(st.st_mode):
                        if st.st_size > limit:
                            problems.append(f"{p}: over {max_filesize_mb} MB, size and mode recorded but not hashed")
                            files[p] = {"type": "file", "size": st.st_size, "mode": stat.S_IMODE(st.st_mode), "sha256": None}
                            continue
                        with open(p, "rb") as f:
                            files[p] = {"type": "file", "size": st.st_size, "mode": stat.S_IMODE(st.st_mode), "sha256": hashlib.file_digest(f, "sha256").hexdigest()}
                except OSError as e:
                    problems.append(f"{p}: {e.strerror}")
    return files, problems


def compare(old: dict, new: dict) -> dict:
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed, mode = [], []
    for p in sorted(set(old) & set(new)):
        a, b = old[p], new[p]
        if (a.get("type"), a.get("sha256"), a.get("target"), a.get("size")) != (b.get("type"), b.get("sha256"), b.get("target"), b.get("size")):
            changed.append(p)
        elif a.get("mode") != b.get("mode"):
            mode.append(p)
    return {"added": added, "removed": removed, "changed": changed, "mode": mode}


def baseline_path(state: Path, cfg: dict) -> Path:
    return Path(cfg["baseline"]).expanduser() if cfg.get("baseline") else state / "integrity-baseline.json"


def load(path: Path):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return None


def save(path: Path, manifest: dict, paths: list, now: str, previous: dict | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"made": now, "paths": [os.path.abspath(os.path.expanduser(p)) for p in paths], "files": manifest}
    if previous:
        doc["replaces"] = {"made": previous.get("made"), "files": len(previous.get("files", {}))}
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, indent=0, sort_keys=True))
    os.replace(tmp, path)


def _names(items: list, n: int = 6) -> str:
    return ", ".join(items[:n]) + (f" and {len(items) - n} more" if len(items) > n else "")


def integrity_check(cfg: dict, state: Path) -> list:
    paths = cfg.get("paths", [])
    if not paths:
        return [Result("integrity.config", "File integrity", "na", "no paths in the integrity section: nothing watched", M_INTEGRITY)]
    bp = baseline_path(state, cfg)
    base = load(bp)
    if base is None:
        return [Result("integrity.baseline", "File integrity baseline", "unknown", f"no baseline yet ({bp}): review the folders, then run `judged integrity init`", M_INTEGRITY)]
    now, problems = scan(paths, cfg.get("exclude", []), cfg.get("max_filesize_mb", 100), cfg.get("max_files", 200000))
    out = []
    watched = {os.path.abspath(os.path.expanduser(p)) for p in paths}
    if watched != set(base.get("paths", [])):
        out.append(Result("integrity.scope", "File integrity scope", "warn",
                          "the watched folders in the config differ from the baseline: files outside one of them show as added or removed; run `judged integrity accept` after review", M_INTEGRITY))
    d = compare(base["files"], now)
    total = len(base["files"])
    if any(d.values()):
        parts = [f"{len(d[k])} {k}: {_names(d[k])}" for k in ("changed", "added", "removed", "mode") if d[k]]
        out.append(Result("integrity.files", "File integrity", "warn", f"since {base.get('made', '?')} of {total} files: " + "; ".join(parts), M_INTEGRITY))
    else:
        out.append(Result("integrity.files", "File integrity", "pass", f"{total} files unchanged since {base.get('made', '?')}", M_INTEGRITY))
    if problems:
        out.append(Result("integrity.scan", "File integrity coverage", "unknown", f"{len(problems)} problems, so the result above may be short: " + _names(problems, 4), M_INTEGRITY))
    return out
