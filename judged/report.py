"""One readable report.md for people who are not admins: what to do first, then what to look at, then the detail per framework."""
import json
from datetime import date, datetime
from pathlib import Path

from . import controls

HEAD = {"fail": "Fix first", "warn": "Look at these", "unknown": "Could not be checked"}
HELP = {
    "fail": "Something is wrong or exposed right now.",
    "warn": "Not an emergency, but a person should decide.",
    "unknown": "judged could not tell (offline, missing tool, no permission). This is not a pass.",
}


def build(results: list, only: str | None = None, today: date | None = None) -> str:
    today = today or date.today()
    n = {s: sum(1 for r in results if r.status == s) for s in ("fail", "warn", "unknown", "pass", "na")}
    out = [f"# Security and compliance report\n\n_{today}. Machine evidence only; policy and process controls need a person._\n",
           f"**{n['fail']} to fix, {n['warn']} to review, {n['unknown']} could not be checked, {n['pass']} fine.**\n"]
    for status in ("fail", "warn", "unknown"):
        rows = [r for r in results if r.status == status]
        if not rows:
            continue
        out.append(f"## {HEAD[status]} ({len(rows)})\n\n_{HELP[status]}_\n")
        out += [f"- **{r.title}**: {r.evidence}" for r in sorted(rows, key=lambda r: r.title)]
        out.append("")
    if n["pass"]:
        out.append(f"## Fine ({n['pass']})\n\n" + ", ".join(sorted(r.title for r in results if r.status == "pass")) + "\n")
    out.append("---\n\n# Detail per framework\n")
    out.append(controls.markdown(controls.load_frameworks(), results, only, today))
    return "\n".join(out)


def summary(results: list, today: date | None = None) -> tuple:
    """(state, title, body) for a phone: state ok|warn|fail, one line of counts, the worst items first. The full report travels as a file."""
    n = {s: sum(1 for r in results if r.status == s) for s in ("fail", "warn", "unknown", "pass")}
    state = "fail" if n["fail"] else ("warn" if n["warn"] or n["unknown"] else "ok")
    title = f"judged audit: {n['fail']} to fix, {n['warn']} to review" + (f", {n['unknown']} unchecked" if n["unknown"] else "")
    first = sorted((r for r in results if r.status == "fail"), key=lambda r: r.title)
    lines = [f"{today or date.today()}: {n['fail']} to fix, {n['warn']} to review, {n['unknown']} could not be checked, {n['pass']} fine."]
    lines += [f"- {r.title}: {r.evidence[:140]}" for r in first[:5]]
    if len(first) > 5:
        lines.append(f"...and {len(first) - 5} more to fix. Full report attached.")
    elif first:
        lines.append("Full report attached.")
    return state, title, "\n".join(lines)


def dump(results: list) -> str:
    return json.dumps([{"id": r.id, "title": r.title, "status": r.status, "evidence": r.evidence} for r in results], indent=1, ensure_ascii=False)


def save(text: str, folder: Path, now: datetime | None = None, results: list | None = None) -> Path:
    """A dated copy that is kept, plus raport.md = the newest (and raport-STAMP.json beside it, for `judged diff`). Returns the raport.md path."""
    folder.mkdir(parents=True, exist_ok=True)
    stamp = (now or datetime.now()).strftime("%Y%m%d-%H%M%S")
    (folder / f"raport-{stamp}.md").write_text(text, encoding="utf-8")
    if results is not None:
        (folder / f"raport-{stamp}.json").write_text(dump(results), encoding="utf-8")
    latest = folder / "raport.md"
    tmp = folder / "raport.md.tmp"
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(latest)
    return latest


def newest(folder: Path) -> Path | None:
    """raport.md if there is one, else the newest dated file (a damaged or half-copied folder still answers)."""
    latest = folder / "raport.md"
    if latest.is_file():
        return latest
    dated = sorted(folder.glob("raport-*.md")) if folder.is_dir() else []
    return dated[-1] if dated else None


SEVERITY = {"fail": 3, "warn": 2, "unknown": 1, "pass": 0, "na": 0}


def load_results(path: Path) -> dict:
    """{id: {...}} from a saved raport-*.json; a damaged file is an error that names the file."""
    try:
        rows = json.loads(Path(path).read_text(encoding="utf-8"))
        return {r["id"]: r for r in rows}
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise ValueError(f"{path}: not a judged result file ({e})") from None


def last_two(folder: Path) -> tuple | None:
    files = sorted(folder.glob("raport-*.json")) if folder.is_dir() else []
    return (files[-2], files[-1]) if len(files) >= 2 else None


def diff(old: dict, new: dict) -> dict:
    """What changed between two runs, by result id. 'worse' and 'better' compare severity: fail > warn > unknown > pass."""
    out = {"new_problems": [], "resolved": [], "worse": [], "better": [], "changed_text": [], "gone": [], "same": 0}
    for i, n in new.items():
        o = old.get(i)
        sn = SEVERITY.get(n["status"], 0)
        if o is None:
            if sn:
                out["new_problems"].append((n, None))
            continue
        so = SEVERITY.get(o["status"], 0)
        if sn > so:
            (out["new_problems"] if so == 0 else out["worse"]).append((n, o))
        elif sn < so:
            (out["resolved"] if sn == 0 else out["better"]).append((n, o))
        elif n["evidence"] != o["evidence"] and sn:
            out["changed_text"].append((n, o))
        else:
            out["same"] += 1
    out["gone"] = [o for i, o in old.items() if i not in new and SEVERITY.get(o["status"], 0)]
    return out


def render_diff(d: dict, old_label: str, new_label: str) -> str:
    def rows(title, items, show_old=False):
        if not items:
            return []
        out = [f"## {title} ({len(items)})", ""]
        for n, o in sorted(items, key=lambda x: x[0]["title"]):
            arrow = f" (was {o['status']})" if o else ""
            out.append(f"- **{n['title']}**: {n['status']}{arrow}. {n['evidence']}")
        return out + [""]
    out = [f"# What changed\n\n_{old_label} -> {new_label}_\n"]
    out += rows("New problems", d["new_problems"]) + rows("Got worse", d["worse"]) + rows("Resolved", d["resolved"]) + rows("Got better", d["better"])
    out += rows("Still a problem, text changed", d["changed_text"])
    if d["gone"]:
        out += [f"## No longer reported ({len(d['gone'])})", "", "_These had a problem last time and are not in this run (area switched off or item removed). Not the same as fixed._", ""]
        out += [f"- {o['title']} (was {o['status']})" for o in sorted(d["gone"], key=lambda o: o["title"])] + [""]
    out.append(f"Unchanged: {d['same']} results.")
    return "\n".join(out)


def has_regression(d: dict) -> bool:
    return bool(d["new_problems"] or d["worse"])
