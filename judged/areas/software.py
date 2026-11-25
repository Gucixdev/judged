"""Licences of installed Python packages, and dependencies of projects (vulnerabilities, licences, accepted waivers)."""
import glob
from pathlib import Path

from .. import deps, licences, waivers

NAME, ORDER = "software", 80


def run(cfg, ctx):
    out, lc, dp = [], cfg.get("licences", {}), cfg.get("deps", {})
    for site in lc.get("envs", []):
        for s in sorted(glob.glob(str(Path(site).expanduser()))):
            out.append(licences.env_check(s, lc.get("deny", []), [p.lower() for p in lc.get("reviewed_packages", [])]))
    waived = [e for e in cfg.get("item", []) if e["kind"] == "waive"]
    seen = set()
    for pat in dp.get("projects", []):
        for r in sorted(glob.glob(str(Path(pat).expanduser()))):
            if Path(r).is_dir():
                out += deps.project(r, dp.get("deny") or lc.get("deny", []), dp.get("max_lookups", 300), waived=waived, today=ctx.today, seen=seen)
    return out + waivers.summary(waived, ctx.today, seen)
