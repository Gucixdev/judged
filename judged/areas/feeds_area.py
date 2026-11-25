"""Public lists (judged/feeds/): download or reuse the cached copy, report how fresh each is, hand the data to the areas that run later.

Also the official texts judged leans on (`source` lines, shipped in catalog.conf). judged cannot turn a legal text into checks, it
tells you that the source changed since a person read it: the marker is a short hash of what `match=` finds there (of the whole
download without it). After reading, write `source ID seen=MARKER` in your config."""
import hashlib
import re
from types import SimpleNamespace

from .. import conf, feeds
from ..controls import M_UPDATES
from ..statement import Alert, Result

NAME, ORDER = "feeds", 5
SPEC = {"feeds": ((), {"enabled": "bool", "online": "bool", "max_age_days": "int", "skip": "list"}, "section"),
        "source": ((("id", "str"),), {"name": "str", "url": "str", "match": "str", "seen": "str"}, "item")}
DEFAULTS = {"feeds": {"enabled": True, "online": True, "max_age_days": 7, "skip": []}}
DOC = {"feeds": "enabled = use public lists (CISA known-exploited vulnerabilities, ...) and watch the official texts in the `source` lines; "
                "online = download them when older than max_age_days (a plain GET, nothing about you is sent), off = use only the cached copy; "
                "skip = list or source names to leave out"}
LEVEL = {"fresh": "pass", "stale": "warn", "none": "unknown"}


def marker(raw: bytes, match: str) -> dict:
    """{"mark": what identifies this version, "found": the last few matches, for a person to read}."""
    found = []
    if match:
        found = sorted({m.group(0) for m in re.finditer(match.encode(), raw)})
        if not found:
            raise ValueError("match= finds nothing: the page changed or the pattern is wrong")
        raw = b"\n".join(found)
    return {"mark": hashlib.sha256(raw).hexdigest()[:12], "found": [x.decode(errors="replace")[:90] for x in found[-5:]]}


def sources(cfg: dict) -> list:
    """The shipped sources with your lines laid over them by id; new ids add your own."""
    out: dict = {}
    for e in conf.catalog()["item"] + cfg.get("item", []):
        if e["kind"] == "source":
            out.setdefault(e["id"], {}).update(e)
    return list(out.values())


def _load(e: dict, f: dict, ctx) -> tuple:
    url, match = e.get("url", ""), e.get("match", "")
    key = hashlib.sha256(f"{url}\n{match}".encode()).hexdigest()[:8]          # a new url or pattern must not reuse the old copy
    feed = SimpleNamespace(NAME=f"source-{e['id']}-{key}", URL=url, parse=lambda raw: marker(raw, match))
    return feeds.load(feed, ctx.state, ctx.today, f.get("max_age_days", 7), f.get("online", True))


def _watched(cfg: dict) -> list:
    f = cfg.get("feeds")
    return [e for e in sources(cfg) if e["id"] not in f.get("skip", [])] if f and f.get("enabled", True) else []


def news(cfg: dict, ctx, last: dict) -> list:
    """An Alert per source that could be read, with a title only for a new marker: the first sight of a source is just remembered,
    unless it already differs from the `seen=` you wrote."""
    out = []
    for e in _watched(cfg):
        data = _load(e, cfg["feeds"], ctx)[0] if e.get("url") else None
        if data is None:
            continue
        key, mark, seen = f"source:{e['id']}", data["mark"], e.get("seen", "")
        before = last.get(key, seen or mark)
        title = f"judged: {e.get('name', e['id'])} changed" if mark not in (before, seen) else ""
        out.append(Alert(key, mark, title, f"marker {before} -> {mark}; read {e['url']}"))
    return out


def _watch(e: dict, f: dict, ctx) -> Result:
    url, seen = e.get("url", ""), e.get("seen", "")
    rid, title = f"source.{e['id']}", f"official text: {e.get('name', e['id'])}"
    if not url:
        return Result(rid, title, "unknown", "no url= (a misspelt id in your config?)")
    data, state, sentence = _load(e, f, ctx)
    if data is None:
        return Result(rid, title, "unknown", sentence)
    now = f"marker {data['mark']}" + (f" ({', '.join(data['found'])})" if data["found"] else "")
    status = LEVEL[state]
    if seen != data["mark"]:
        status = "warn"
        now = (f"CHANGED since your review (you read {seen}): " if seen else "nobody has reviewed it yet: ") + \
              f"{now}; read {url}, then write `source {e['id']} seen={data['mark']}`"
    return Result(rid, title, status, now if state == "fresh" else f"{now}; {sentence}")


def run(cfg, ctx):
    f = cfg.get("feeds")
    if not f or not f.get("enabled", True):
        return []
    skip = f.get("skip", [])
    out, shared = [], ctx.shared.setdefault("feeds", {})
    for feed in feeds.discover():
        if feed.NAME in skip:
            continue
        data, state, sentence = feeds.load(feed, ctx.state, ctx.today, f.get("max_age_days", 7), f.get("online", True))
        shared[feed.NAME] = data
        out.append(Result(f"feeds.{feed.NAME}", f"public list: {feed.DOC}", LEVEL[state], sentence, M_UPDATES))
    return out + [_watch(e, f, ctx) for e in _watched(cfg)]
