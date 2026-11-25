"""Contracts, DPAs, suppliers, insurance, trademarks: the date that costs money is not the end of the term but the last day to give notice.

    contract "Hosting" 2027-03-31 type=supplier notice_days=90 auto_renews=1 term_months=12 cost=24000 currency=EUR owner=anna vendor=Acme

`end` is the end of the current term. With `auto_renews=1` an `end` in the past is rolled forward by whole terms (nobody edits the date after every
renewal). The alert date (same bands as every other item) is `end - notice_days`. After that day an auto-renewing contract is locked in for
another term, and the result says what that term costs. `cost` is the price of ONE term; a cost without a currency is reported, never summed."""
import calendar
from datetime import date, datetime, timedelta, timezone

from .controls import Result
from .core import Item

TYPES = ("contract", "supplier", "dpa", "insurance", "trademark")
M_SUPPLIERS = {"iso27001": ["A.5.19", "A.5.20"], "gdpr": ["art28"]}


def add_months(d: date, n: int) -> date:
    y, m = divmod(d.month - 1 + n, 12)
    y, m = d.year + y, m + 1
    return date(y, m, min(d.day, calendar.monthrange(y, m)[1]))


def terms(e: dict, today: date) -> dict:
    """end (rolled forward for auto-renewals), notice_by, how many terms were rolled."""
    end, step, rolled = e["expires"], e.get("term_months", 12), 0
    if e.get("auto_renews"):
        while end < today:
            rolled += 1
            end = add_months(e["expires"], step * rolled)
    notice_by = end - timedelta(days=e.get("notice_days", 0))
    return {"end": end, "notice_by": notice_by, "rolled": rolled}


def _money(e: dict) -> str:
    return f"{e['cost']:g} {e['currency']}" if "cost" in e and e.get("currency") else (f"{e['cost']:g} (no currency)" if "cost" in e else "")


def items(cfg: dict, today: date | None = None) -> list:
    today = today or datetime.now(timezone.utc).date()
    out = []
    for e in cfg.get("item", []):
        if e["kind"] != "contract":
            continue
        t = terms(e, today)
        d = t["notice_by"]
        label = f"{e['name']} notice deadline" if e.get("notice_days") else e["name"]
        out.append(Item("contract", label, datetime(d.year, d.month, d.day, tzinfo=timezone.utc),
                        {k: v for k, v in e.items() if k not in ("kind", "name", "expires")}))
    return out


def _one(e: dict, today: date, warn_days: int) -> Result:
    name, typ = e["name"], e.get("type", "contract")
    rid, maps = f"paperwork.{name.lower().replace(' ', '-')}", (M_SUPPLIERS if typ in ("contract", "supplier", "dpa") else {})
    title = f"{typ} {name}"
    if typ not in TYPES:
        return Result(rid, title, "unknown", f"type '{typ}' is not one of {', '.join(TYPES)}", maps)
    t = terms(e, today)
    end, nb = t["end"], t["notice_by"]
    auto, money = bool(e.get("auto_renews")), _money(e)
    notes = []
    if not e.get("owner"):
        notes.append("no owner: nobody is named to act")
    if "cost" in e and not e.get("currency"):
        notes.append("cost has no currency")
    if t["rolled"]:
        notes.append(f"end date rolled forward {t['rolled']} term(s) because it auto-renews: write the real one down")
    tail = ("; " + "; ".join(notes)) if notes else ""
    if end < today:
        return Result(rid, title, "fail", f"ended {(today - end).days} days ago ({end}) and does not auto-renew: renew it or remove it from the list" + tail, maps)
    n = (nb - today).days
    if n < 0:
        if auto:
            return Result(rid, title, "fail", f"notice deadline passed {-n} days ago ({nb}): it renews on {end} for another {e.get('term_months', 12)} months"
                          + (f", cost {money}" if money else "") + tail, maps)
        return Result(rid, title, "warn", f"notice date passed {-n} days ago ({nb}); ends {end}" + tail, maps)
    if n <= warn_days:
        return Result(rid, title, "warn", f"{n} days to decide ({nb}), ends {end}" + (f"; if you do nothing it renews for {money}" if auto and money else "") + tail, maps)
    return Result(rid, title, "warn" if notes else "pass", f"next deadline {nb} in {n} days, ends {end}" + tail, maps)


def audit(cfg: dict, today: date, warn_days: int = 30) -> list:
    rows = [e for e in cfg.get("item", []) if e["kind"] == "contract"]
    out = [_one(e, today, warn_days) for e in rows]
    risk: dict = {}
    for e, r in zip(rows, out):
        if e.get("auto_renews") and r.status in ("fail", "warn") and "cost" in e:
            risk[e.get("currency") or "?"] = risk.get(e.get("currency") or "?", 0) + e["cost"]
    if risk:
        out.append(Result("paperwork.exposure", "money locked in or about to be", "warn",
                          "auto-renewing contracts past or near their notice deadline: " + ", ".join(f"{v:g} {c if c != '?' else '(no currency)'}" for c, v in sorted(risk.items())), {}))
    return out
