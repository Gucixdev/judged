import json
from datetime import date, timedelta
from types import SimpleNamespace

import pytest

from judged import deps, feeds, vulninfo
from judged.areas import Ctx, feeds_area
from judged.feeds import kev

TODAY = date(2026, 11, 25)
KEV_RAW = json.dumps({"vulnerabilities": [
    {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2020-0001", "dateAdded": "2022-01-01", "dueDate": "2022-01-22"}]}).encode()
FEED = SimpleNamespace(NAME="demo", URL="https://example.invalid/demo.json", DOC="demo list", parse=lambda raw: json.loads(raw))


def cached(tmp_path, data, fetched):
    p = tmp_path / "feeds"
    p.mkdir()
    (p / "demo.json").write_text(json.dumps({"fetched": fetched.isoformat(), "url": "x", "data": data}))


def boom(url):
    raise OSError("no route")


def test_kev_parse():
    assert kev.parse(KEV_RAW) == {"CVE-2021-44228": ["2021-12-10", "2021-12-24", "Known"], "CVE-2020-0001": ["2022-01-01", "2022-01-22", "Unknown"]}


def test_download_when_no_cache_writes_json(tmp_path):
    asked = []
    data, st, text = feeds.load(FEED, tmp_path, TODAY, fetch=lambda u: asked.append(u) or b'{"a": 1}')
    assert (data, st, asked) == ({"a": 1}, "fresh", [FEED.URL])
    saved = json.loads((tmp_path / "feeds" / "demo.json").read_text())
    assert saved == {"fetched": "2026-11-25", "url": FEED.URL, "data": {"a": 1}}
    assert not (tmp_path / "feeds" / "demo.tmp").exists()
    assert "downloaded 2026-11-25" in text


def test_fresh_cache_is_not_downloaded(tmp_path):
    cached(tmp_path, {"old": 1}, TODAY - timedelta(days=7))
    data, st, text = feeds.load(FEED, tmp_path, TODAY, max_age_days=7, fetch=boom)
    assert (data, st) == ({"old": 1}, "fresh") and "7 day(s) old" in text


def test_older_than_max_age_downloads(tmp_path):
    cached(tmp_path, {"old": 1}, TODAY - timedelta(days=8))
    data, st, _ = feeds.load(FEED, tmp_path, TODAY, max_age_days=7, fetch=lambda u: b'{"new": 2}')
    assert (data, st) == ({"new": 2}, "fresh")


def test_failed_download_uses_stale_cache_and_says_so(tmp_path):
    cached(tmp_path, {"old": 1}, TODAY - timedelta(days=30))
    data, st, text = feeds.load(FEED, tmp_path, TODAY, fetch=boom)
    assert (data, st) == ({"old": 1}, "stale")
    assert "2026-10-26" in text and "30 days old" in text and "no route" in text
    assert json.loads((tmp_path / "feeds" / "demo.json").read_text())["data"] == {"old": 1}


def test_offline_by_config_never_downloads(tmp_path):
    cached(tmp_path, {"old": 1}, TODAY - timedelta(days=30))
    data, st, text = feeds.load(FEED, tmp_path, TODAY, online=False, fetch=lambda u: pytest.fail("downloaded"))
    assert (data, st) == ({"old": 1}, "stale") and "offline by config" in text
    assert feeds.load(FEED, tmp_path / "empty", TODAY, online=False, fetch=boom)[:2] == (None, "none")


def test_nothing_at_all_is_none(tmp_path):
    data, st, text = feeds.load(FEED, tmp_path, TODAY, fetch=boom)
    assert (data, st) == (None, "none") and text.startswith("no demo list")


def test_corrupt_cache_counts_as_missing(tmp_path):
    (tmp_path / "feeds").mkdir()
    (tmp_path / "feeds" / "demo.json").write_text("{not json")
    assert feeds.load(FEED, tmp_path, TODAY, fetch=lambda u: b"[1]")[:2] == ([1], "fresh")
    (tmp_path / "feeds" / "demo.json").write_text(json.dumps({"fetched": "yesterday", "data": 1}))
    assert feeds.load(FEED, tmp_path, TODAY, fetch=boom)[:2] == (None, "none")


def test_unparseable_download_keeps_old_cache(tmp_path):
    cached(tmp_path, {"old": 1}, TODAY - timedelta(days=30))
    data, st, _ = feeds.load(FEED, tmp_path, TODAY, fetch=lambda u: b"<html>captive portal</html>")
    assert (data, st) == ({"old": 1}, "stale")


def test_future_dated_cache_is_not_trusted(tmp_path):
    cached(tmp_path, {"old": 1}, TODAY + timedelta(days=3))
    assert feeds.load(FEED, tmp_path, TODAY, fetch=lambda u: b'{"n": 1}')[:2] == ({"n": 1}, "fresh")


def test_size_limit(monkeypatch):
    class R:
        def __init__(self, n): self.n = n
        def read(self, k): return b"x" * min(self.n, k)
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(feeds.urllib.request, "urlopen", lambda req, timeout: R(feeds.MAX_BYTES + 5))
    with pytest.raises(OSError, match="larger than 30 MB"):
        feeds.fetch_bytes("https://example.invalid/")
    monkeypatch.setattr(feeds.urllib.request, "urlopen", lambda req, timeout: R(10))
    assert feeds.fetch_bytes("https://example.invalid/") == b"x" * 10


@pytest.fixture
def lists_only(monkeypatch):
    monkeypatch.setattr(feeds_area, "sources", lambda cfg: [])     # the watched texts have their own tests


def test_discover_finds_kev():
    assert "kev" in [f.NAME for f in feeds.discover()]


def test_area_results_and_shared(tmp_path, monkeypatch, lists_only):
    monkeypatch.setattr(feeds, "fetch_bytes", lambda u: KEV_RAW)
    monkeypatch.setattr(feeds, "discover", lambda: [kev])
    ctx = Ctx(TODAY, tmp_path)
    cfg = {"feeds": {"enabled": True, "online": True, "max_age_days": 7, "skip": []}}
    [r] = feeds_area.run(cfg, ctx)
    assert (r.id, r.status) == ("feeds.kev", "pass") and "CVE-2021-44228" in ctx.shared["feeds"]["kev"]
    assert feeds_area.run({"feeds": {**cfg["feeds"], "skip": ["kev"]}}, Ctx(TODAY, tmp_path)) == []
    assert feeds_area.run({"feeds": {**cfg["feeds"], "enabled": False}}, Ctx(TODAY, tmp_path)) == []


def test_area_offline_without_cache_is_unknown(tmp_path, monkeypatch, lists_only):
    monkeypatch.setattr(feeds, "fetch_bytes", boom)
    monkeypatch.setattr(feeds, "discover", lambda: [kev])
    ctx = Ctx(TODAY, tmp_path)
    [r] = feeds_area.run({"feeds": {"enabled": True, "online": True, "max_age_days": 7, "skip": []}}, ctx)
    assert r.status == "unknown" and ctx.shared["feeds"]["kev"] is None


def test_area_stale_is_warn(tmp_path, monkeypatch, lists_only):
    monkeypatch.setattr(feeds, "discover", lambda: [kev])
    (tmp_path / "feeds").mkdir()
    (tmp_path / "feeds" / "kev.json").write_text(json.dumps({"fetched": "2026-01-01", "url": "x", "data": {}}))
    [r] = feeds_area.run({"feeds": {"enabled": True, "online": False, "max_age_days": 7, "skip": []}}, Ctx(TODAY, tmp_path))
    assert r.status == "warn"


KEV_MAP = {"CVE-2021-44228": ["2021-12-10", "2021-12-24", "Known"]}
HIT = {("Maven", "log4j-core", "2.14.0"): ["GHSA-jfh8-c2jp-5v3q"], ("npm", "lodash", "4.17.15"): ["GHSA-x"]}


def test_exploited_unknown_without_list():
    r = deps.exploited("app", HIT, {}, None, 40)
    assert r.status == "unknown" and r.id == "deps.app.exploited"


def test_exploited_fails_through_alias():
    r = deps.exploited("app", HIT, {"GHSA-jfh8-c2jp-5v3q": {"CVE-2021-44228"}}, KEV_MAP, 40)
    assert r.status == "fail"
    assert "log4j-core 2.14.0: CVE-2021-44228 (added 2021-12-10, fix due 2021-12-24, used in ransomware)" in r.evidence
    assert "lodash" not in r.evidence


def test_exploited_matches_cve_id_without_alias_and_notes_cut():
    hit = {("PyPI", "x", "1"): ["CVE-2021-44228"]}
    r = deps.exploited("app", hit, {}, KEV_MAP, 0)
    assert r.status == "fail" and "ids beyond the first 0" in r.evidence


def test_exploited_pass_when_nothing_matches():
    r = deps.exploited("app", HIT, {"GHSA-x": {"CVE-2099-1"}}, KEV_MAP, 40)
    assert r.status == "pass" and "none of the open" in r.evidence


def test_exploited_ransomware_flag_only_when_known():
    r = deps.exploited("app", {("PyPI", "x", "1"): ["CVE-2020-0001"]}, {}, {"CVE-2020-0001": ["2022-01-01", "2022-01-22", "Unknown"]}, 40)
    assert r.status == "fail" and "ransomware" not in r.evidence


def test_details_fills_aliases():
    aliases = {}
    get = lambda url: {"id": "GHSA-a", "aliases": ["CVE-2021-1", "OSV-9"], "database_specific": {}}
    vulninfo.details({("npm", "a", "1"): ["GHSA-a"]}, get, 40, aliases)
    assert aliases == {"GHSA-a": {"CVE-2021-1"}}


def test_project_checks_waived_vulnerability_too(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/a": {"version": "1.0.0", "resolved": "https://r/a.tgz"}}}))
    post = lambda url, body: {"results": [{"vulns": [{"id": "GHSA-a"}]} for _ in body["queries"]]}
    get = lambda url: {"id": "GHSA-a", "aliases": ["CVE-2021-44228"]} if "GHSA-a" in url else {"licenses": ["MIT"]}
    waived = [{"id": "GHSA-a", "expires": date(2027, 1, 1), "owner": "alice", "reason": "x"}]
    res = {r.id.rsplit(".", 1)[1]: r for r in deps.project(str(tmp_path), [], post=post, get=get, waived=waived, today=TODAY, kev=KEV_MAP)}
    assert res["exploited"].status == "fail" and "CVE-2021-44228" in res["exploited"].evidence
