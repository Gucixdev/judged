"""Host hardening audits: one file per audit, found automatically, so a new audit never touches the others. A file here has

    NAME  = "mything"              # id part (hardening.mything), the name `skip=` uses, and shown when the audit itself breaks
    ORDER = 40                     # position in the report
    def check(cfg, env): return [Result(...), ...]       # cfg = the `hardening` section of the config, env = Env below

`Env` is everything an audit may touch on the machine (a file, a kernel setting, a command). Tests hand in a fake one, so an audit is
proved against exact inputs without the real machine. An audit that raises becomes ONE `unknown` result; the others still run.
What an audit cannot read (no permission, no tool) is `unknown`, never `pass`."""
import importlib
import pkgutil
from .. import inits
import subprocess
from pathlib import Path

from ..controls import Result


class Env:
    def read(self, path: str) -> str:
        return Path(path).read_text(errors="replace")

    def sysctl(self, key: str):
        try:
            return Path("/proc/sys/" + key.replace(".", "/")).read_text().strip()
        except OSError:
            return None

    def run(self, cmd: list, timeout: int = 20) -> tuple:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.returncode, r.stdout
        except (OSError, subprocess.TimeoutExpired):
            return None, ""

    def head(self, path: str, n: int = 64) -> str:
        with open(path, "rb") as f:
            return f.read(n).decode("utf-8", "replace")

    def stat(self, path: str) -> tuple:
        """(permission bits, modified time as epoch seconds)"""
        s = Path(path).stat()
        return s.st_mode & 0o7777, s.st_mtime

    def home(self) -> str:
        return str(Path.home())

    def service(self, units: list) -> tuple:
        """(True up | False down | None cannot ask, which unit, init system name): see judged/inits."""
        return inits.active(units, self.run)

    def listdir(self, path: str) -> list:
        return sorted(p.name for p in Path(path).iterdir())


def discover() -> list:
    mods = [importlib.import_module(f"{__name__}.{m.name}") for m in pkgutil.iter_modules(__path__)]
    return sorted((m for m in mods if hasattr(m, "check")), key=lambda m: (getattr(m, "ORDER", 500), m.NAME))


def names() -> list:
    return [m.NAME for m in discover()]


def run_all(cfg: dict, env=None) -> list:
    env, out, skip = env or Env(), [], set(cfg.get("skip", []))
    unknown = skip - set(names())
    if unknown:                                            # a typo in `skip=` would silently switch nothing off
        out.append(Result("hardening.config", "Hardening config", "warn", f"skip names no audit has: {', '.join(sorted(unknown))} (known: {', '.join(names())})"))
    for m in discover():
        if m.NAME in skip:
            continue
        try:
            out += m.check(cfg, env)
        except Exception as e:                             # one broken audit must not hide the rest or look like a pass
            out.append(Result(f"hardening.{m.NAME}", f"Hardening: {m.NAME}", "unknown", f"audit crashed: {type(e).__name__}: {e}"))
    return out
