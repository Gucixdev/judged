"""Calendar of recurring obligations per region: periodic ones become expiry Items (same alert bands),
event-driven ones are shown with their deadline."""
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from .core import Item


def catalog() -> list:
    from . import conf
    return conf.catalog()["duties"]


STALE_DAYS = 180


def unreviewed(entry: dict, today: date | None = None) -> bool:
    """A legal entry is trusted only while a person has reviewed it recently (`reviewed = YYYY-MM-DD`)."""
    r = entry.get("reviewed")
    return r is None or ((today or date.today()) - r).days > STALE_DAYS


def for_regions(regions: list, cat: list | None = None) -> list:
    cat = cat if cat is not None else catalog()
    want = {r.upper() for r in regions}
    return [o for o in cat if not want or want & set(o["region"])]


def items(cfg: dict, cat: list | None = None) -> list:
    """Periodic obligations the company has a `last_done` date for, as Items due at last_done + cadence."""
    by_id = {o["id"]: o for o in (cat if cat is not None else catalog())}
    out = []
    for e in cfg.get("obligation", []):
        o = by_id.get(e["id"])
        if not o or o["kind"] != "periodic" or "last_done" not in e:
            continue
        d = e["last_done"]
        base = datetime(d.year, d.month, d.day, tzinfo=timezone.utc)
        out.append(Item("obligation", o["title"], base + timedelta(days=o["cadence_days"])))
    return out


def _line(o: dict, today: date | None) -> list:
    flag = "[UNREVIEWED] " if unreviewed(o, today) else ""
    return [f"  {flag}{o['framework']}: {o['title']}"]


def report(cfg: dict, today: date | None = None) -> str:
    """Obligations of the configured regions, grouped like bought licences: overdue, then one block per year of the due date,
    then the ones with no `last_done` yet (no date, so no year) and the event-driven ones with their deadline."""
    today = today or date.today()
    regions = cfg.get("company", {}).get("regions", [])
    done = {e["id"]: e for e in cfg.get("obligation", [])}
    dated, unscheduled, events = [], [], []
    for o in for_regions(regions):
        e = done.get(o["id"])
        if o["kind"] != "periodic":
            events.append(o)
        elif not e or "last_done" not in e:
            unscheduled.append(o)
        else:
            dated.append((e["last_done"] + timedelta(days=o["cadence_days"]), o))
    dated.sort(key=lambda x: (x[0], x[1]["id"]))
    out = [f"as of {today}, regions: {', '.join(regions) or 'all'}"]
    year = None
    for due, o in dated:
        head = "Overdue" if due < today else str(due.year)
        if head != year:
            year = head
            out.append(f"\n{head}")
        out += [f"  {due}  every {o['cadence_days']} d" + (" (" + str((today - due).days) + " days late)" if due < today else "")]
        out += _line(o, today) + [f"          verify: {o['verify']}"]
    if unscheduled:
        out.append("\nNo date yet (set last_done in the config)")
        for o in unscheduled:
            out += _line(o, today) + [f"          every {o['cadence_days']} d; verify: {o['verify']}"]
    if events:
        out.append("\nEvent-driven (no calendar date)")
        for o in events:
            out += _line(o, today) + [f"          deadline: {o['deadline']}", f"          verify: {o['verify']}"]
    known = {o["id"] for o in (catalog())}
    bad = [i for i in done if i not in known]
    if bad:
        out.append("\nUnknown obligation id in the config (typo? it is ignored): " + ", ".join(bad)
                   + "\n  known ids: " + ", ".join(sorted(known)))
    return "\n".join(out)
