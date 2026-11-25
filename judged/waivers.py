"""Accepted vulnerabilities: `waive ID EXPIRY owner=NAME reason="..." [package=NAME]` in judged.conf.
A waiver is a decision by a named person that ends on a date. judged never honours one that has no owner or no reason, or that
has run out (the finding comes back), and it says when a waiver matches nothing any more, so the list cannot rot."""
from datetime import date, timedelta

from .controls import M_UPDATES, Result

SOON_DAYS = 14


def split(raw: list, today: date) -> tuple:
    """(active, problems): active waivers are valid and not expired; problems are human-readable strings."""
    active, problems = [], []
    for w in raw:
        label = w["id"] + (f" ({w['package']})" if w.get("package") else "")
        if not w.get("owner") or not w.get("reason"):
            problems.append(f"{label} ignored: needs owner= and reason= (a waiver is somebody's decision)")
        elif w["expires"] < today:
            problems.append(f"{label} expired on {w['expires']} (owner {w['owner']}): the finding counts again, renew or fix it")
        else:
            active.append(w)
    return active, problems


def apply(hit: dict, active: list, today: date, seen: set | None = None) -> tuple:
    """hit {(eco, name, version): [ids]} -> (remaining hit, [waived descriptions]). `seen` collects every waiver id that matched."""
    left, waived = {}, []
    for pkg, ids in hit.items():
        rest = []
        for i in ids:
            w = next((w for w in active if w["id"] == i and w.get("package", pkg[1]) == pkg[1]), None)
            if w is None:
                rest.append(i)
                continue
            if seen is not None:
                seen.add((w["id"], w.get("package")))
            soon = (w["expires"] - today) <= timedelta(days=SOON_DAYS)
            waived.append(f"{i} in {pkg[1]} until {w['expires']} by {w['owner']}" + (" (ends soon)" if soon else ""))
        if rest:
            left[pkg] = rest
    return left, waived


def summary(raw: list, today: date, seen: set) -> list:
    """One result for the whole list: invalid and expired ones, and ones that match nothing in this run."""
    if not raw:
        return []
    active, problems = split(raw, today)
    unused = [w["id"] for w in active if (w["id"], w.get("package")) not in seen]
    if unused:
        problems.append("no longer matches any finding, remove it: " + ", ".join(unused[:8]))
    if problems:
        return [Result("deps.waivers", "Accepted vulnerabilities (waivers)", "warn", "; ".join(problems), M_UPDATES)]
    return [Result("deps.waivers", "Accepted vulnerabilities (waivers)", "pass",
                   f"{len(active)} active, each with owner, reason and end date; next ends {min(w['expires'] for w in active)}", M_UPDATES)]
