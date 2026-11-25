"""Public lists (judged/feeds/): download or reuse the cached copy, report how fresh each is, hand the data to the areas that run later."""
from .. import feeds
from ..controls import M_UPDATES, Result

NAME, ORDER = "feeds", 5
SPEC = {"feeds": ((), {"enabled": "bool", "online": "bool", "max_age_days": "int", "skip": "list"}, "section")}
DEFAULTS = {"feeds": {"enabled": True, "online": True, "max_age_days": 7, "skip": []}}
DOC = {"feeds": "enabled = use public lists (CISA known-exploited vulnerabilities, ...) in the checks; online = download them when older than max_age_days "
                "(a plain GET, nothing about you is sent), off = use only the cached copy; skip = list names to leave out"}
LEVEL = {"fresh": "pass", "stale": "warn", "none": "unknown"}


def run(cfg, ctx):
    f = cfg.get("feeds")
    if not f or not f.get("enabled", True):
        return []
    out, shared = [], ctx.shared.setdefault("feeds", {})
    for feed in feeds.discover():
        if feed.NAME in f.get("skip", []):
            continue
        data, state, sentence = feeds.load(feed, ctx.state, ctx.today, f.get("max_age_days", 7), f.get("online", True))
        shared[feed.NAME] = data
        out.append(Result(f"feeds.{feed.NAME}", f"public list: {feed.DOC}", LEVEL[state], sentence, M_UPDATES))
    return out
