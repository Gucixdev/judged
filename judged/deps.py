"""Dependencies of every project under a folder: known vulnerabilities (OSV) and licences (deps.dev, Packagist), from lockfiles.
Sends only public registry package names and versions to those two services, never paths, never the project name.
Network trouble is `unknown`, never `pass`."""
import json
import urllib.request
from pathlib import Path

from datetime import date

from . import licsources, lockfiles, vulninfo, waivers as waiv
from .controls import M_UPDATES, Result
from .licences import M_LICENCE, RANK, classify

OSV = "https://api.osv.dev/v1/querybatch"


def post_json(url: str, body: dict) -> dict:
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=20) as r:
        return json.load(r)


def vulns(pkgs: list, post=post_json) -> dict:
    """{(eco, name, version): [ids]} for packages with at least one known vulnerability."""
    hit = {}
    for i in range(0, len(pkgs), 1000):
        chunk = pkgs[i:i + 1000]
        res = post(OSV, {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]})["results"]
        for p, r in zip(chunk, res):
            if r.get("vulns"):
                hit[p] = [v["id"] for v in r["vulns"]]
    return hit


def licence_of(pkg: tuple, get=get_json) -> str | None:
    """The licence text from the source that covers this ecosystem (judged/licsources/), None when none does or the version is not found."""
    eco, name, ver = pkg
    src = licsources.find(eco)
    return src.licence(eco, name, ver, get) if src else None


def _vuln_line(pkg, ids, worst) -> str:
    """name version (worst id, severity score, fix hint): the worst of the package's ids, the others only counted."""
    _, n, v = pkg
    i, lab, score, fixed = worst
    more = f", +{len(ids) - 1} more" if len(ids) > 1 else ""
    return f"{n} {v} ({i} {lab.lower()}{f' {score}' if score is not None else ''}{more}; " + (f"fixed in {fixed}, loose version order" if fixed else "no fixed version listed above yours") + ")"


def exploited(name: str, hit: dict, aliases: dict, kev: dict | None, limit: int) -> Result:
    """Which vulnerable packages have a CVE on the CISA list of vulnerabilities attackers already use. Certain, so it is a fail."""
    rid, title = f"deps.{name}.exploited", f"{name} actively exploited vulnerabilities"
    if kev is None:
        return Result(rid, title, "unknown", "CISA known-exploited list not available (feeds area off, offline or no cache)", M_UPDATES)
    rows = []
    for pkg in sorted(hit):
        for vid in hit[pkg]:
            for cve in sorted({vid} | aliases.get(vid, set())):
                if cve in kev:
                    rows.append(f"{pkg[1]} {pkg[2]}: {cve} (added {kev[cve][0]}, fix due {kev[cve][1]}" + (", used in ransomware" if str(kev[cve][2]).lower() == "known" else "") + ")")
    rows = sorted(set(rows))
    cut = sum(len(v) for v in hit.values()) > limit
    note = f"; ids beyond the first {limit} were matched by their own CVE id only" if cut else ""
    if rows:
        return Result(rid, title, "fail", f"{len(rows)} on the CISA list: " + "; ".join(rows[:5]) + (f"; (+{len(rows) - 5} more)" if len(rows) > 5 else "") + note, M_UPDATES)
    return Result(rid, title, "pass", "none of the open vulnerabilities is on the CISA known-exploited list" + note, M_UPDATES)


def project(root: str, deny: list, max_lookups: int = 300, post=post_json, get=get_json, waived: list | None = None, max_vuln_details: int = 40,
            today: date | None = None, seen: set | None = None, kev: dict | None = None) -> list:
    name = Path(root).expanduser().name
    files = lockfiles.find(root)
    if not files:
        return [Result(f"deps.{name}.lockfiles", f"{name} dependencies", "unknown",
                       "no lockfile found (package-lock.json, Cargo.lock, composer.lock, go.mod, poetry/uv/Pipfile.lock, requirements.txt)", M_UPDATES)]
    pkgs, errs = [], []
    for f in files:
        got, err = lockfiles.read(f)
        pkgs += got
        if err:
            errs.append(err)
    pkgs = sorted(set(pkgs))
    out = [Result(f"deps.{name}.lockfiles", f"{name} lockfiles", "warn" if errs else "pass",
                  "; ".join(errs) if errs else f"{len(files)} lockfiles, {len(pkgs)} registry packages", M_UPDATES)]
    try:
        hit, accepted = vulns(pkgs, post), []
        every = {p: list(v) for p, v in hit.items()}
        if waived:
            hit, accepted = waiv.apply(hit, waiv.split(waived, today or date.today())[0], today or date.today(), seen)
        aliases = {}
        info = vulninfo.details(hit, get, max_vuln_details, aliases)
        waived_only = {p: [i for i in ids if i not in hit.get(p, [])] for p, ids in every.items()}
        waived_only = {p: ids for p, ids in waived_only.items() if ids}
        if waived_only and kev is not None:
            vulninfo.details(waived_only, get, max_vuln_details, aliases)
        rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        worst = {p: max(rows, key=lambda r: rank.get(r[1], 0)) for p, rows in info.items()}
        order = sorted(hit, key=lambda p: -rank.get(worst[p][1], 0))
        ev = "; ".join(_vuln_line(p, hit[p], worst[p]) for p in order[:5]) + (f"; (+{len(order) - 5} more)" if len(order) > 5 else "")
        note = f"; waived: {'; '.join(accepted[:3])}" + (f" (+{len(accepted) - 3} more)" if len(accepted) > 3 else "") if accepted else ""
        bad = [p for p in hit if rank.get(worst[p][1], 0) >= 3]
        cut = [f"severity looked up for the first {max_vuln_details} ids only"] if sum(len(v) for v in hit.values()) > max_vuln_details else []
        out.append(Result(f"deps.{name}.vulns", f"{name} known vulnerabilities", "fail" if bad else "warn" if hit else "pass",
                          (f"{len(hit)} of {len(pkgs)} packages ({len(bad)} high or critical): {ev}" + "".join("; " + c for c in cut) if hit else f"none open in {len(pkgs)} packages (OSV)") + note, M_UPDATES))
        out.append(exploited(name, every, aliases, kev, max_vuln_details))
    except OSError as e:
        out.append(Result(f"deps.{name}.vulns", f"{name} known vulnerabilities", "unknown", f"OSV not reachable: {e}", M_UPDATES))
    by, denied, skipped = {}, [], 0
    known = licsources.covered()
    todo = [p for p in pkgs if p[0] in known]
    for p in todo[:max_lookups]:
        try:
            lic = licence_of(p, get)
        except OSError:
            lic = None
        cls, label = classify(lic or "")
        by.setdefault(cls, []).append(f"{p[1]} ({label})")
        if label in deny:
            denied.append(f"{p[1]} ({label})")
    skipped = len(todo) - min(len(todo), max_lookups)
    summary = ", ".join(f"{len(v)} {k}" for k, v in sorted(by.items(), key=lambda kv: RANK[kv[0]]))
    notes = ([f"{skipped} not looked up (max_lookups)"] if skipped else []) + \
            ([f"{len(pkgs) - len(todo)} in ecosystems no licence source covers"] if len(pkgs) > len(todo) else [])
    flagged = by.get("restricted", []) + by.get("strong-copyleft", []) + by.get("unknown", [])
    st = "fail" if denied else ("warn" if flagged or notes else "pass")
    ev = (f"denied: {', '.join(denied[:5])}. " if denied else "") + (f"review: {', '.join(flagged[:5])}. " if flagged else "") + summary
    out.append(Result(f"deps.{name}.licences", f"{name} dependency licences", st, "; ".join([ev] + notes), M_LICENCE))
    return out
