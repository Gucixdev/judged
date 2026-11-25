"""What no machine check can prove, as dated statements a person answers for:

    review "Risk assessment" months=12 last=2026-03-01 owner=anna proof=~/audit/risk.pdf maps=iso27001:A.5.15
    certification "Cyber Essentials" 2027-04-30 number=IASME-123 issuer="Body Ltd" scope="whole company" owner=anna proof=URL maps=ce:firewalls
    notapplicable iso27001 A.8.28 owner=anna reason="we write no software"

A statement passes only with an owner and a proof (a URL, a ticket id, or a file; an absolute or ~ path must exist). It counts as
marked as a statement: a control with nothing measured behind it reads `pass (statements only)`. Review due dates and certificate expiry alert like any other date."""
import os
from datetime import date, datetime, timezone

from .. import conf
from ..contracts import add_months
from ..controls import Result
from ..core import Item

NAME, ORDER = "assurance", 72
_COMMON = {"owner": "str", "proof": "str", "maps": "maps"}
SPEC = {"review": ((("name", "str"),), {"months": "int", "last": "date", **_COMMON}, "item"),
        "certification": ((("name", "str"), ("expires", "date")), {"number": "str", "issuer": "str", "scope": "str", **_COMMON}, "item"),
        "notapplicable": ((("framework", "str"), ("id", "str")), {"owner": "str", "reason": "str"}, "item")}


def _due(e: dict) -> date | None:
    """The day the statement stops counting; None for a review that was never done."""
    if e["kind"] == "certification":
        return e["expires"]
    return add_months(e["last"], e.get("months", 12)) if "last" in e else None


def items(cfg: dict, today: date) -> list:
    return [Item(e["kind"], e["name"], datetime(d.year, d.month, d.day, tzinfo=timezone.utc), {"owner": e.get("owner", "")})
            for e in cfg.get("item", []) if e["kind"] in ("review", "certification") and (d := _due(e))]


def _unknown_maps(maps: dict, known: dict) -> list:
    bad = [f"{fw}:{c}" for fw, ids in maps.items() for c in ids if c not in known.get(fw, {})]
    return [f"maps= names no known control: {', '.join(bad)}"] if bad else []


def _statement(e: dict, today: date, warn_days: int, known: dict) -> Result:
    kind, name, proof, maps = e["kind"], e["name"], e.get("proof", ""), e.get("maps", {})
    problems = _unknown_maps(maps, known)
    if not e.get("owner"):
        problems.append("no owner=: nobody answers for it")
    if not proof:
        problems.append("no proof=: only a claim")
    elif proof.startswith(("/", "~")) and not os.path.exists(os.path.expanduser(proof)):
        problems.append(f"proof file {proof} is not there")
    due = _due(e)
    if due is None or e.get("last", today) > today:
        status, text = "fail", "never done (no last=)" if due is None else f"last={e['last']} is in the future"
    elif due < today:
        status, text = "fail", f"{'expired' if kind == 'certification' else 'overdue since'} {due}"
    else:
        status = "warn" if problems or (due - today).days <= warn_days else "pass"
        text = f"{'valid until' if kind == 'certification' else 'next due'} {due} ({(due - today).days} days)"
    facts = [f"{k} {e[k]}" for k in ("number", "issuer", "scope") if e.get(k)]
    facts += [f"owner {e['owner']}"] if e.get("owner") else []
    facts += [f"proof {proof}"] if proof else []
    return Result(f"{kind}.{name.lower().replace(' ', '-')}", f"{kind} {name}", status,
                  "; ".join([text, *facts, *problems]), maps, attested=True)


def _excluded(e: dict, known: dict) -> Result:
    fw, cid = e["framework"], e["id"]
    problems = _unknown_maps({fw: [cid]}, known)
    if not (e.get("owner") and e.get("reason")):
        problems.append("ignored: needs owner= and reason=")
    text = "; ".join(problems) or f"does not apply: {e['reason']} (decided by {e['owner']})"
    return Result(f"notapplicable.{fw}.{cid}", f"scope of {fw} {cid}", "warn" if problems else "na", text, {fw: [cid]}, attested=True)


def run(cfg, ctx):
    known = {k: dict(v["controls"]) for k, v in conf.catalog()["frameworks"].items()}
    for k, v in cfg.get("frameworks", {}).items():
        known.setdefault(k, {}).update(v["controls"])
    warn_days = max(cfg.get("notify", {}).get("lead_days", [30]))
    return [_excluded(e, known) if e["kind"] == "notapplicable" else _statement(e, ctx.today, warn_days, known)
            for e in cfg.get("item", []) if e["kind"] in SPEC]
