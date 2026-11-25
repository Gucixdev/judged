"""Which init system runs this machine, and is a service up. One file per init system, found automatically. A file here has

    NAME = "dinit"
    def detect(pid1: str, exists) -> bool          # pid1 = /proc/1/comm, exists = os.path.exists (or a fake)
    def active(unit: str, run) -> bool | None      # True up, False down, None "could not ask" (daemon unreachable, tool missing)

`run(cmd) -> (returncode | None, stdout)`. A new init system is a new file, nothing else changes. Service NAMES differ between
distributions, so callers pass every name they know and get the first one that is up. If the init system is unknown, or cannot be
asked, the answer is None: callers must report that as `unknown`, never as "not running" and never as a pass."""
import importlib
import os
import pkgutil


def discover() -> list:
    return [importlib.import_module(f"{__name__}.{m.name}") for m in pkgutil.iter_modules(__path__)]


def current(read=None, exists=os.path.exists):
    """(module or None, the PID 1 name)."""
    try:
        pid1 = (read or (lambda p: open(p).read()))("/proc/1/comm").strip()
    except OSError:
        return None, ""
    for m in discover():
        if m.detect(pid1, exists):
            return m, pid1
    return None, pid1


def active(units, run, read=None, exists=os.path.exists) -> tuple:
    """(state, which, init name). state True if any unit is up, False if all answered 'down', None if nothing could be asked."""
    m, pid1 = current(read, exists)
    if m is None:
        return None, "", pid1 or "unknown"
    answers = [(u, m.active(u, run)) for u in units]
    up = [u for u, a in answers if a]
    if up:
        return True, up[0], m.NAME
    return (False if any(a is False for _, a in answers) else None), "", m.NAME
