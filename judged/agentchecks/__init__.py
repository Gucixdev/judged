"""Audits of what an AI coding agent may do on this machine: one file per audit, found automatically.

    NAME  = "mcp"
    ORDER = 20
    def check(cfg, env): return [Result(...), ...]       # cfg = the `agents` section, env = Env below

Findings come as (level, text) pairs, level "fail" for what is certain to be a problem (a literal secret in a config, permission
checks switched off) and "warn" for what depends on intent (an unpinned server, a broad allow rule), so a reader can decide on the
warnings and cannot overlook the failures. Secret values are never put into a text, only the name and the file.
An audit that raises becomes ONE `unknown` result; the others still run."""
import glob as _glob
import importlib
import json
import pkgutil
import subprocess
from pathlib import Path

from ..controls import Result

M_AGENTS = {"ce": ["secure-config", "user-access"], "iso27001": ["A.8.9", "A.8.2"], "gdpr": ["art32"]}


class Env:
    def read(self, path: str, limit: int = 2_000_000):
        try:
            with open(path, "rb") as f:
                return f.read(limit).decode("utf-8", "replace")
        except OSError:
            return None

    def mode(self, path: str):
        try:
            return Path(path).stat().st_mode & 0o7777
        except OSError:
            return None

    def glob(self, pattern: str) -> list:
        return sorted(_glob.glob(str(Path(pattern).expanduser())))

    def home(self) -> str:
        return str(Path.home())

    def git(self, repo: str, *args: str) -> tuple:
        try:
            r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, timeout=20)
            return r.returncode, r.stdout
        except (OSError, subprocess.TimeoutExpired):
            return None, ""


def load_json(env, path: str):
    """(data, None) | (None, why). A missing file is (None, None): nothing to audit."""
    text = env.read(path)
    if text is None:
        return None, None
    try:
        return json.loads(text), None
    except ValueError as e:
        return None, f"not valid JSON ({str(e)[:60]})"


def repos(cfg, env) -> list:
    return sorted({r for pat in cfg.get("repos", []) for r in env.glob(pat)})


def verdict(rid: str, title: str, findings: list, ok: str) -> Result:
    level = "fail" if any(l == "fail" for l, _ in findings) else "warn" if findings else "pass"
    body = "; ".join(t for _, t in sorted(findings, key=lambda f: f[0] != "fail")) if findings else ok
    return Result(rid, title, level, body, M_AGENTS)


def discover() -> list:
    mods = [importlib.import_module(f"{__name__}.{m.name}") for m in pkgutil.iter_modules(__path__)]
    return sorted((m for m in mods if hasattr(m, "check")), key=lambda m: (getattr(m, "ORDER", 500), m.NAME))


def run_all(cfg: dict, env=None) -> list:
    env, out, skip = env or Env(), [], set(cfg.get("skip", []))
    for m in discover():
        if m.NAME in skip:
            continue
        try:
            out += m.check(cfg, env)
        except Exception as e:
            out.append(Result(f"agents.{m.NAME}", f"agent audit {m.NAME}", "unknown", f"the audit stopped: {type(e).__name__}: {str(e)[:100]}", M_AGENTS))
    return out
