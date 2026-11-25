"""Link audit: symlinks (working, broken, loops, pointing into temp folders) and files with more than one name (hardlinks).

Report only. judged never repairs, replaces or deletes a link: that is a job for a tool that is allowed to change things (a separate tool)."""
import errno
import fnmatch
import os
import stat
from dataclasses import dataclass, field

from .controls import Result
from .integrity import M_INTEGRITY

M_LINKS = M_INTEGRITY
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")


@dataclass
class Scan:
    links: list = field(default_factory=list)        # (path, target text, state, dest) state: ok | broken | loop | denied
    multi: dict = field(default_factory=dict)        # (dev, inode) -> [nlink, [names found], special]  files with several names
    entries: int = 0
    problems: list = field(default_factory=list)     # words: unreadable folder, stopped at max_files


def _skip(path, name, exclude):
    return any(fnmatch.fnmatch(name, g) or fnmatch.fnmatch(path, g) for g in exclude)


def _state(path):
    """(state, absolute destination): follow the link the way a program would."""
    try:
        os.stat(path)
    except FileNotFoundError:
        return "broken", ""
    except PermissionError:
        return "denied", ""
    except OSError as e:
        return ("loop" if e.errno == errno.ELOOP else "broken"), ""
    return "ok", os.path.realpath(path)


def scan(paths, exclude=(), max_files=200000) -> Scan:
    out = Scan()
    stack = [os.path.expanduser(p) for p in paths]
    while stack:
        d = stack.pop()
        try:
            it = list(os.scandir(d))
        except OSError as e:
            out.problems.append(f"cannot read {d} ({e.strerror or 'error'})")
            continue
        for e in sorted(it, key=lambda x: x.name):
            if _skip(e.path, e.name, exclude):
                continue
            out.entries += 1
            if out.entries > max_files:
                out.problems.append(f"stopped after {max_files} entries: the rest was not looked at")
                return out
            try:
                st = e.stat(follow_symlinks=False)
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                state, dest = _state(e.path)
                out.links.append((e.path, os.readlink(e.path), state, dest))
            elif stat.S_ISDIR(st.st_mode):
                stack.append(e.path)
            elif stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
                m = out.multi.setdefault((st.st_dev, st.st_ino), [st.st_nlink, [], bool(st.st_mode & (stat.S_ISUID | stat.S_ISGID))])
                m[1].append(e.path)
    return out


def _brief(items, n=5):
    return "; ".join(items[:n]) + (f" (+{len(items) - n} more)" if len(items) > n else "")


def links_check(cfg: dict) -> list:
    paths = cfg.get("paths", [])
    if not paths:
        return [Result("links.config", "Links", "na", "no paths in the links section: nothing scanned", M_LINKS)]
    s = scan(paths, cfg.get("exclude", []), cfg.get("max_files", 200000))
    bad = [(p, t, st) for p, t, st, _ in s.links if st in ("broken", "loop")]
    denied = [p for p, _, st, _ in s.links if st == "denied"]
    out = [Result("links.broken", "Broken symlinks", "warn" if bad else "pass",
                  (f"{len(bad)} of {len(s.links)} symlinks lead nowhere: " + _brief([f"{p} -> {t} ({'loop' if st == 'loop' else 'target missing'})" for p, t, st in bad])
                   + ". Nothing was changed: judged only reports") if bad else f"{len(s.links)} symlinks, every one leads to something", M_LINKS)]
    risky = [f"{p} -> {d}" for p, _, _, d in s.links if d.startswith(TEMP_DIRS) and not os.path.abspath(p).startswith(TEMP_DIRS)]
    out.append(Result("links.temp_target", "Symlinks into temp folders", "warn" if risky else "pass",
                      f"{len(risky)} symlinks point into /tmp-like folders, which other users can write to: {_brief(risky)}" if risky else "no symlink points into /tmp, /var/tmp or /dev/shm", M_LINKS))
    names = {k: v for k, v in s.multi.items()}
    special = [f"{', '.join(v[1][:2])} ({v[0]} names, setuid/setgid)" for v in names.values() if v[2]]
    out.append(Result("links.hardlinks", "Files with several names (hardlinks)", "warn" if special else "pass",
                      (f"a setuid/setgid file has more than one name, so an update of one name leaves the old program reachable under the other: {_brief(special)}" if special
                       else f"{len(names)} files have several names" + (f", for example {names[next(iter(names))][1][0]}" if names else "") + "; none is setuid or setgid"), M_LINKS))
    gaps = s.problems + ([f"{len(denied)} symlinks could not be followed (permission): {_brief(denied, 3)}"] if denied else [])
    if gaps:
        out.append(Result("links.coverage", "Link scan coverage", "unknown", "; ".join(gaps) + ": not everything was looked at", M_LINKS))
    return out


def listing(cfg: dict) -> list:
    """Every symlink and every file with several names, one line each, for `judged links`."""
    s = scan(cfg.get("paths", []), cfg.get("exclude", []), cfg.get("max_files", 200000))
    lines = [f"{st.upper():7} {p} -> {t}" for p, t, st, _ in s.links]
    lines += [f"{v[0]} names{' (setuid/setgid)' if v[2] else ''}: {', '.join(v[1])}" for v in s.multi.values()]
    return lines + [f"note: {p}" for p in s.problems]
