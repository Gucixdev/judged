"""Coding-standard checks on source folders: one file per standard, found automatically. A file here has

    NAME  = "misra-c"                    # id part (codestd.<repo>.misra-c) and the name `skip=` uses
    DOC   = "MISRA C:2012 through cppcheck"
    TOOL  = "cppcheck"                   # the program that does the work; missing = `unknown`, never `pass`
    EXTS  = (".c", ".h")
    def command(files: list, cfg: dict) -> list         # argv; cfg = the `codestd` section
    def parse(rc: int, out: str, err: str) -> list      # [(rule, file, line)], or None when the tool itself failed (`err` says why)

A standard that is not met is a `warn`, never a `fail`: a rule list is advice a team decides on (a rule may be deviated from on purpose),
so the reader sees the count, the most frequent rules and the first places, and decides. Nothing is changed in the code.
The standards are written down by their owners (MISRA is a paid document, so its rule texts are never shipped here: `misra_rules`
in the config points at your own copy, and without it the findings carry only the rule number)."""
import importlib
import os
import pkgutil
import shutil
import subprocess
from collections import Counter
from pathlib import Path

from ..controls import Result

M_CODE = {"iso27001": ["A.8.28"]}
SKIP_DIRS = {".git", "node_modules", "vendor", "build", "dist", "target", ".venv", "venv", "__pycache__", "graphify-out", "third_party", "extern"}


class Env:
    def which(self, tool: str):
        return shutil.which(tool)

    def run(self, cmd: list, timeout: int):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            return None, "", f"timed out after {timeout} s"
        except OSError as e:
            return None, "", str(e)

    def files(self, root: str, exts: tuple, limit: int) -> list:
        out = []
        for dp, dirs, names in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for n in sorted(names):
                if n.endswith(exts):
                    out.append(os.path.join(dp, n))
                    if len(out) > limit:
                        return out
        return out


def discover() -> list:
    mods = [importlib.import_module(f"{__name__}.{m.name}") for m in pkgutil.iter_modules(__path__)]
    return sorted((m for m in mods if hasattr(m, "parse")), key=lambda m: m.NAME)


def check_repo(root: str, cfg: dict, env=None, standards: list | None = None) -> list:
    env, out = env or Env(), []
    name = Path(root).expanduser().name
    root = str(Path(root).expanduser())
    for m in standards if standards is not None else discover():
        if m.NAME in cfg.get("skip", []):
            continue
        rid, title = f"codestd.{name}.{m.NAME}", f"{name}: {m.DOC}"
        try:
            limit = cfg.get("max_files", 300)
            files = env.files(root, m.EXTS, limit)
            if not files:
                continue
            if not env.which(m.TOOL):
                out.append(Result(rid, title, "unknown", f"{m.TOOL} is not installed, so {len(files)} files were not checked", M_CODE))
                continue
            cut = len(files) > limit
            files = files[:limit]
            rc, so, se = env.run(m.command(files, cfg), cfg.get("timeout", 300))
            if rc is None:
                out.append(Result(rid, title, "unknown", f"{m.TOOL} did not run: {se[:100]}", M_CODE))
                continue
            found = m.parse(rc, so, se)
            if found is None:
                out.append(Result(rid, title, "unknown", f"{m.TOOL} failed: {(se or so).strip()[:120]}", M_CODE))
                continue
            out.append(Result(rid, title, "warn" if found else "pass", evidence(found, files, root, cut, limit), M_CODE))
        except Exception as e:
            out.append(Result(rid, title, "unknown", f"the check stopped: {type(e).__name__}: {str(e)[:100]}", M_CODE))
    return out


def evidence(found: list, files: list, root: str, cut: bool, limit: int) -> str:
    note = f"; only the first {limit} files were checked" if cut else ""
    if not found:
        return f"no findings in {len(files)} files{note}"
    top = ", ".join(f"{r} x{n}" for r, n in Counter(r for r, _, _ in found).most_common(3))
    where = ", ".join(f"{os.path.relpath(f, root)}:{ln}" for _, f, ln in found[:3])
    return f"{len(found)} findings in {len({f for _, f, _ in found})} of {len(files)} files; most frequent: {top}; first: {where}{note}"


def run_all(cfg: dict, env=None) -> list:
    out = []
    for pat in cfg.get("repos", []):
        import glob
        for r in sorted(glob.glob(str(Path(pat).expanduser()))):
            if Path(r).is_dir():
                out += check_repo(r, cfg, env)
    return out
