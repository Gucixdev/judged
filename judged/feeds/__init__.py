"""Public lists judged downloads and keeps as JSON in its state folder, so a check can use fresh data and still run offline.
One file per list, found automatically:

    NAME = "kev"                       # cache file feeds/kev.json, id feeds.kev, the name `skip=` uses
    URL  = "https://..."               # what is downloaded; nothing about you is sent, it is a plain GET
    DOC  = "one line: what it is"
    def parse(raw: bytes): ...         # the small JSON-able value the checks need (not the whole download)

`load` returns the data, a state and a sentence: "fresh" (cache younger than max_age_days, or just downloaded), "stale" (older and the
download failed, or offline: the old data is still used and the sentence says how old), "none" (no data at all, checks must say unknown).
A cache that cannot be parsed counts as missing. The cache is written to a temporary file and moved into place."""
import importlib
import json
import pkgutil
import urllib.request
from datetime import date
from pathlib import Path

MAX_BYTES = 30_000_000


def fetch_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "judged/0 public list download"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise OSError(f"download larger than {MAX_BYTES // 1_000_000} MB")
    return data


def discover() -> list:
    mods = [importlib.import_module(f"{__name__}.{m.name}") for m in pkgutil.iter_modules(__path__)]
    return sorted((m for m in mods if hasattr(m, "parse")), key=lambda m: m.NAME)


def _read(path: Path):
    try:
        c = json.loads(path.read_text())
        return c["data"], date.fromisoformat(c["fetched"])
    except (OSError, ValueError, KeyError, TypeError):
        return None, None


def _write(path: Path, data, today: date, url: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"fetched": today.isoformat(), "url": url, "data": data}))
    tmp.replace(path)


def load(feed, state: Path, today: date, max_age_days: int = 7, online: bool = True, fetch=None) -> tuple:
    """(data | None, "fresh" | "stale" | "none", sentence)."""
    path = Path(state) / "feeds" / f"{feed.NAME}.json"
    data, got = _read(path)
    age = (today - got).days if got else None
    if data is not None and age is not None and 0 <= age <= max_age_days:
        return data, "fresh", f"{feed.NAME} list from {got} ({age} day(s) old)"
    why = "offline by config"
    if online:
        try:
            new = feed.parse((fetch or fetch_bytes)(feed.URL))
            _write(path, new, today, feed.URL)
            return new, "fresh", f"{feed.NAME} list downloaded {today}"
        except (OSError, ValueError, KeyError, TypeError) as e:
            why = f"download failed: {str(e)[:80]}"
    if data is not None:
        return data, "stale", f"{feed.NAME} list is from {got} ({age} days old), {why}"
    return None, "none", f"no {feed.NAME} list: {why}"
