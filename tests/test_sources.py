from datetime import date, timedelta

import pytest

from judged import areas, conf, feeds
from judged.areas import feeds_area as f

T = date(2026, 11, 25)
ON = "feeds enabled=1 online=1 max_age_days=7 skip=kev\n"


def watch(tmp_path, extra="", page=b"doc-v3-3.pdf doc-v3-3.pdf other", today=T, monkeypatch=None, cfg=ON):
    def fetch(url):
        if isinstance(page, Exception):
            raise page
        return page
    monkeypatch.setattr(feeds, "fetch_bytes", fetch)
    monkeypatch.setattr(f.conf, "catalog", lambda: conf.parse("source ce name=CE url=https://x/ match='doc-v[0-9-]+[.]pdf'\n"))
    [r] = f.run(conf.parse(cfg + extra), areas.Ctx(today, tmp_path))
    return r


def test_marker_ignores_the_rest_of_the_page_repeats_and_order():
    a = f.marker(b"x v1 y v2 v1", "v[0-9]")
    assert a == f.marker(b"zz v2 other v1", "v[0-9]") and a["found"] == ["v1", "v2"] and len(a["mark"]) == 12
    assert f.marker(b"v1 v3", "v[0-9]")["mark"] != a["mark"] and f.marker(b"v1", "")["mark"] != f.marker(b"v1 ", "")["mark"]
    assert f.marker(b"v1v2v3v4v5v6v7", "v[0-9]")["found"] == ["v3", "v4", "v5", "v6", "v7"]
    with pytest.raises(ValueError, match="finds nothing"):
        f.marker(b"<html>moved</html>", "v[0-9]")


def test_unreviewed_then_reviewed_then_changed(tmp_path, monkeypatch):
    r = watch(tmp_path, monkeypatch=monkeypatch)
    mark = f.marker(b"doc-v3-3.pdf", "doc-v3-3.pdf")["mark"]
    assert (r.id, r.status, r.maps) == ("source.ce", "warn", {}) and "nobody has reviewed it yet" in r.evidence and f"source ce seen={mark}`" in r.evidence
    ok = watch(tmp_path, f"source ce seen={mark}\n", monkeypatch=monkeypatch)
    assert (ok.status, ok.evidence) == ("pass", f"marker {mark} (doc-v3-3.pdf)")
    new = watch(tmp_path, f"source ce seen={mark}\n", page=b"doc-v3-4.pdf", today=T + timedelta(days=8), monkeypatch=monkeypatch)
    assert new.status == "warn" and new.evidence.startswith(f"CHANGED since your review (you read {mark})") and "v3-4" in new.evidence


def test_no_download_is_never_a_pass(tmp_path, monkeypatch):
    mark = f.marker(b"doc-v3-3.pdf", "doc-v3-3.pdf")["mark"]
    down = OSError("down")
    assert watch(tmp_path, page=down, monkeypatch=monkeypatch).status == "unknown"
    assert watch(tmp_path, page=b"<html>captive portal</html>", monkeypatch=monkeypatch).status == "unknown"
    watch(tmp_path, monkeypatch=monkeypatch)
    old = watch(tmp_path, f"source ce seen={mark}\n", page=down, today=T + timedelta(days=30), monkeypatch=monkeypatch)
    assert old.status == "warn" and "30 days old" in old.evidence


def test_a_new_pattern_does_not_reuse_the_old_copy_and_your_ids_are_added_or_skipped(tmp_path, monkeypatch):
    watch(tmp_path, monkeypatch=monkeypatch)
    r = watch(tmp_path, "source ce match=other\n", monkeypatch=monkeypatch)
    assert "(other)" in r.evidence
    assert watch(tmp_path, cfg=ON.replace("skip=kev", "skip=kev,ce") + "source mine url=https://y/\n", monkeypatch=monkeypatch).id == "source.mine"
    typo = watch(tmp_path, cfg=ON.replace("skip=kev", "skip=kev,ce") + "source cee seen=abc\n", monkeypatch=monkeypatch)
    assert typo.status == "unknown" and "no url=" in typo.evidence


def test_shipped_sources_are_complete_and_their_patterns_compile():
    import re
    got = f.sources({})
    assert len(got) == 7 and len({e["id"] for e in got}) == 7
    for e in got:
        assert e["url"].startswith("https://") and e["name"] and re.compile(e["match"].encode()) and "seen" not in e


def test_check_alerts_once_per_new_marker_and_remembers_it_when_offline(tmp_path, monkeypatch, capsys):
    from judged import __main__ as m
    pages, sent, ok = {"now": b"doc-v3-3.pdf"}, [], {"deliver": True}

    def fetch(url):
        if isinstance(pages["now"], Exception):
            raise pages["now"]
        return pages["now"]
    monkeypatch.setattr(feeds, "fetch_bytes", fetch)
    monkeypatch.setattr(f.conf, "catalog", lambda: conf.parse("source ce name=CE url=https://x/ match='doc-v[0-9-]+[.]pdf'\n"))
    monkeypatch.setattr(m, "load", lambda path: conf.parse(ON.replace("max_age_days=7", "max_age_days=-1")))
    monkeypatch.setattr(m.notify, "send", lambda urls, title, body: ok["deliver"] and not sent.append(title))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))

    def go(page, deliver=True):
        pages["now"], ok["deliver"] = page, deliver
        m.once(tmp_path / "c.conf", False)
        return len(sent)
    assert go(b"doc-v3-3.pdf") == 0 and go(b"doc-v3-3.pdf") == 0          # first sight is remembered, not alerted
    assert go(b"doc-v3-4.pdf", deliver=False) == 0 and "not delivered" in capsys.readouterr().err
    assert go(b"doc-v3-4.pdf") == 1 and sent == ["judged: CE changed"]      # retried, then once
    assert go(b"doc-v3-4.pdf") == 1 and go(OSError("down")) == 1 and go(b"doc-v3-4.pdf") == 1
    assert go(b"doc-v3-5.pdf") == 2


def test_a_marker_that_differs_from_your_review_alerts_at_first_sight(tmp_path, monkeypatch):
    watch(tmp_path, monkeypatch=monkeypatch)
    cfg = conf.parse(ON + "source ce seen=oldmark\n")
    [a] = f.news(cfg, areas.Ctx(T, tmp_path), {})
    key, mark, title, body = a.key, a.value, a.title, a.body
    assert key == "source:ce" and title == "judged: CE changed" and body.startswith(f"marker oldmark -> {mark}")
    assert f.news(cfg, areas.Ctx(T, tmp_path), {key: mark})[0].title == ""
    assert f.news(conf.parse(ON + f"source ce seen={mark}\n"), areas.Ctx(T, tmp_path), {key: "older"})[0].title == ""   # you already read it
