"""Contracts, DPAs, suppliers, insurance and trademarks with a notice period: `contract NAME END ...`."""
from datetime import date

from .. import contracts

NAME, ORDER = "paperwork", 70
SPEC = {"contract": ((("name", "str"), ("expires", "date")),
                     {"type": "str", "notice_days": "int", "auto_renews": "bool", "term_months": "int", "cost": "float", "currency": "str", "vendor": "str", "owner": "str"}, "item")}


items = contracts.items


def run(cfg, ctx):
    return contracts.audit(cfg, ctx.today, max(cfg.get("notify", {}).get("lead_days", [30])))
