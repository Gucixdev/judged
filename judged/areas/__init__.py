"""Audit areas: one file per area, found automatically. To add a new kind of check, drop a file here with

    NAME  = "mything"            # shown when the area itself breaks
    ORDER = 55                   # position in the report (lower runs first)
    SPEC  = {"mything": ((), {"paths": "list"}, "section")}     # the config lines it understands (same form as conf.SPEC); optional
    DEFAULTS = {"mything": {"paths": []}}; DOC = {"mything": "one line for the template"}   # every SPEC key needs a default (a test checks)
    def run(cfg, ctx): return [Result(...), ...]                # cfg = the loaded config, ctx = Ctx below
    def items(cfg, today): return [core.Item(...), ...]         # optional: dates that `check` and `run` alert on
    def news(cfg, ctx, last): return [statement.Alert(...), ...]  # optional: other alerts from `check`/`run`; `last` = key -> value
                                                                # kept from the previous pass

Nothing else changes: not `audit()`, not `conf.py`. An area that raises becomes ONE `unknown` result that says so, and the other
areas still run: a broken check must never hide the rest, and never look like a pass."""
import importlib
import pkgutil
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path


@dataclass
class Ctx:
    today: date
    state: Path                                            # judged's own state folder
    shared: dict = field(default_factory=dict)             # areas may hand data to a later one (ORDER decides who is later)


def discover() -> list:
    mods = [importlib.import_module(f"{__name__}.{m.name}") for m in pkgutil.iter_modules(__path__)]
    return sorted((m for m in mods if hasattr(m, "run")), key=lambda m: (getattr(m, "ORDER", 500), m.__name__))


def specs() -> dict:
    out = {}
    for m in discover():
        out.update(getattr(m, "SPEC", {}))
    return out


def defaults() -> dict:
    out = {}
    for m in discover():
        out.update(getattr(m, "DEFAULTS", {}))
    return out


def docs() -> dict:
    out = {}
    for m in discover():
        out.update(getattr(m, "DOC", {}))
    return out


def items(cfg: dict, today: date) -> list:
    """Every dated item the areas know of."""
    return [i for m in discover() if hasattr(m, "items") for i in m.items(cfg, today)]


def news(cfg: dict, ctx: Ctx, last: dict) -> list:
    return [n for m in discover() if hasattr(m, "news") for n in m.news(cfg, ctx, last)]


def run_all(cfg: dict, ctx: Ctx) -> list:
    from ..controls import M_CONFIG, Result
    results = []
    for m in discover():
        name = getattr(m, "NAME", m.__name__.rsplit(".", 1)[-1])
        try:
            results += m.run(cfg, ctx)
        except Exception as e:                             # noqa: BLE001 - one broken area must not hide the others
            results.append(Result(f"area.{name}", f"Audit area {name}", "unknown", f"the area crashed ({type(e).__name__}: {e}); nothing from it is in this report", M_CONFIG))
    return results
