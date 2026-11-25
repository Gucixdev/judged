"""Result model and the roll-up of checks into framework controls. A control with no automated
evidence is 'manual' (a person must supply it); it is never reported as passed."""
from datetime import date
from dataclasses import dataclass, field
from pathlib import Path

# maps used by checks: framework -> control ids
M_FIREWALL = {"ce": ["firewalls"], "iso27001": ["A.8.20"], "gdpr": ["art32"]}
M_CONFIG = {"ce": ["secure-config"], "iso27001": ["A.8.9"], "gdpr": ["art32"]}
M_ACCESS = {"ce": ["user-access"], "iso27001": ["A.5.15", "A.8.2", "A.8.5"], "gdpr": ["art32"]}
M_MALWARE = {"ce": ["malware"], "iso27001": ["A.8.7"], "gdpr": ["art32"]}
M_UPDATES = {"ce": ["updates"], "iso27001": ["A.8.8"], "gdpr": ["art32"]}
M_LOGGING = {"iso27001": ["A.8.15"], "gdpr": ["art32"]}
M_MAIL = {"gdpr": ["art32"]}
M_CRYPTO = {"ce": ["secure-config"], "iso27001": ["A.8.24"], "gdpr": ["art32", "art5-1f"]}


@dataclass
class Result:
    id: str
    title: str
    status: str            # pass | warn | fail | unknown (could not check) | na
    evidence: str
    maps: dict = field(default_factory=dict)


def load_frameworks(path: Path | None = None) -> dict:
    from . import conf
    return (conf.load(path) if path else conf.catalog())["frameworks"]


def control_status(results: list) -> str:
    seen = {r.status for r in results if r.status != "na"}
    if not seen:
        return "manual"
    for s in ("fail", "warn", "unknown"):
        if s in seen:
            return s
    return "pass"


def assemble(key: str, fw: dict, results: list) -> list:
    rows = []
    for cid, title in fw["controls"].items():
        rs = [r for r in results if cid in r.maps.get(key, [])]
        rows.append((cid, title, control_status(rs), rs))
    return rows


def markdown(frameworks: dict, results: list, only: str | None = None, today: date | None = None) -> str:
    today = today or date.today()
    out = [f"_Report as of {today}._\n"]
    for key, fw in frameworks.items():
        if only and key != only:
            continue
        rows = assemble(key, fw, results)
        n = {s: sum(1 for r in rows if r[2] == s) for s in ("pass", "warn", "fail", "unknown", "manual")}
        r = fw.get("reviewed")
        flag = " [UNREVIEWED control list]" if r is None or (today - r).days > 180 else f" (control list reviewed {r})"
        out.append(f"## {fw['name']}{flag}\n\n" + ", ".join(f"{v} {k}" for k, v in n.items() if v) + "\n")
        out.append("| Control | Status | Evidence |\n|---|---|---|")
        for cid, title, st, rs in rows:
            ev = "; ".join(f"{r.title}: {r.evidence}" for r in rs) or "no automated evidence, a person must supply it"
            out.append(f"| {cid} {title} | {st} | {ev.replace('|', '/')} |")
        out.append("")
    out.append("_Automated machine evidence only. Not a certification; policy and process controls need people._")
    return "\n".join(out)
