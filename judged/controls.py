"""Framework controls: which checks are evidence for which, and the tables that show it."""
from datetime import date
from pathlib import Path

from .statement import Result, control_status, shown

# maps used by checks: framework -> control ids. A Cyber Essentials id (judged/catalog.conf) is one requirement, so only a check
# whose result bears on a requirement names it. What the NCSC text does not ask for (backups, TLS, logging, encryption) names none.
M_FIREWALL = {"iso27001": ["A.8.20"], "gdpr": ["art32"]}
M_CONFIG = {"iso27001": ["A.8.9"], "gdpr": ["art32"]}
M_ACCESS = {"iso27001": ["A.5.15", "A.8.2", "A.8.5"], "gdpr": ["art32"]}
M_MALWARE = {"iso27001": ["A.8.7"], "gdpr": ["art32"]}       # no ce: on Linux NCSC lists allow listing, not anti-malware software
M_VULN = {"iso27001": ["A.8.8"], "gdpr": ["art32"]}
M_LOGGING = {"iso27001": ["A.8.15"], "gdpr": ["art32"]}
M_MAIL = {"gdpr": ["art32"]}
M_CRYPTO = {"iso27001": ["A.8.24"], "gdpr": ["art32", "art5-1f"]}


def _ce(maps: dict, *ids: str) -> dict:
    return {**maps, "ce": list(ids)}


M_HOST_FIREWALL = _ce(M_FIREWALL, "fw-every-device", "fw-untrusted-networks")
M_SERVICES = _ce(M_FIREWALL, "cfg-software")                 # what listens on the network
M_UNUSED = _ce(M_VULN, "cfg-software")                       # installed and not needed
M_UPDATES = _ce(M_VULN, "upd-14-days")                       # fixes that are waiting
M_PASSWORD_LOGIN = _ce(M_ACCESS, "acc-guessing")
M_PRIVILEGES = _ce(M_ACCESS, "acc-privileges")


def load_frameworks(path: Path | None = None) -> dict:
    from . import conf
    return (conf.load(path) if path else conf.catalog())["frameworks"]


def assemble(key: str, fw: dict, results: list) -> list:
    rows = []
    for cid, title in fw["controls"].items():
        rs = [r for r in results if cid in r.maps.get(key, [])]
        rows.append((cid, title, control_status(rs, fw.get("confirm", False)), rs))
    return rows


CONFIRM_NOTE = ("_A requirement covers every device and service in scope; judged measures the machine it runs on. A measurement can fail a "
                "requirement, a pass also needs a person's statement (`judged config reviews` prints them)._")
STATUSES = ("pass", "warn", "fail", "unknown", "manual", "n/a")


def _sections(frameworks: dict, results: list, only: str | None, today: date):
    """(heading with status counts, rows) for each framework asked for."""
    for key, fw in frameworks.items():
        if only and key != only:
            continue
        rows = assemble(key, fw, results)
        n = {s: sum(1 for r in rows if r[2] == s) for s in STATUSES}
        r = fw.get("reviewed")
        flag = " [UNREVIEWED control list]" if r is None or (today - r).days > 180 else f" (control list reviewed {r})"
        note = f"\n{CONFIRM_NOTE}\n" if fw.get("confirm") else ""
        yield f"## {fw['name']}{flag}\n{note}\n" + ", ".join(f"{v} {k}" for k, v in n.items() if v) + "\n", rows


def _cell(parts: list, empty: str) -> str:
    return ("; ".join(parts) or empty).replace("|", "/")


def markdown(frameworks: dict, results: list, only: str | None = None, today: date | None = None) -> str:
    today = today or date.today()
    out = [f"_Report as of {today}._\n"]
    for head, rows in _sections(frameworks, results, only, today):
        out += [head, "| Control | Status | Evidence |\n|---|---|---|"]
        out += [f"| {cid} {title} | {shown(st, rs)} | {_cell([f'{r.title}: {r.evidence}' for r in rs], 'no evidence yet, a person must supply it')} |"
                for cid, title, st, rs in rows]
        out.append("")
    out.append("_`pass (statements only)` rests on what people stated, with owner and proof; nothing was measured. This report is not a certificate._")
    return "\n".join(out)


def soa(frameworks: dict, results: list, only: str | None = None, today: date | None = None) -> str:
    """Statement of applicability: per control, whether it applies and what proves it, then what is still open before an audit."""
    today = today or date.today()
    out = [f"# Statement of applicability\n\n_{today}._\n"]
    for head, rows in _sections(frameworks, results, only, today):
        out += [head, "| Control | Applies | Status | Proven by, or why not |\n|---|---|---|---|"]
        for cid, title, st, rs in rows:
            proof = [r.evidence if st == "n/a" else f"{r.title} ({'statement' if r.attested else 'measured'}, {r.status})" for r in rs]
            out.append(f"| {cid} {title} | {'no' if st == 'n/a' else 'yes'} | {shown(st, rs)} | {_cell(proof, 'nothing yet')} |")
        todo = [f"{label}: {', '.join(ids)}" for label, wanted in (("failing", ("fail",)), ("to review", ("warn", "unknown")), ("needs a person", ("manual",)))
                if (ids := [cid for cid, _, st, _ in rows if st in wanted])]
        out.append("\nOpen before an audit: " + ("; ".join(todo) if todo else "nothing that judged knows of") + ".\n")
    out.append("_This lists what judged has on file. A certificate comes from a certification body and its assessor decides what is enough; "
               "one check rarely covers every requirement of a control._")
    return "\n".join(out)
