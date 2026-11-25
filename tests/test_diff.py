import json
from datetime import datetime

import pytest

from judged import report
from judged.controls import Result


def row(i, status, ev="e", title=None):
    return {"id": i, "title": title or i, "status": status, "evidence": ev}


def d(old, new):
    return report.diff({r["id"]: r for r in old}, {r["id"]: r for r in new})


def test_every_kind_of_change_lands_in_its_own_bucket():
    old = [row("a", "pass"), row("b", "fail"), row("c", "warn"), row("d", "warn", "x"), row("e", "fail"), row("gone", "fail"), row("gone-ok", "pass"), row("same", "fail", "s")]
    new = [row("a", "fail"), row("b", "pass"), row("c", "fail"), row("d", "warn", "y"), row("e", "warn"), row("same", "fail", "s"), row("fresh", "warn"), row("fresh-ok", "pass")]
    r = d(old, new)
    ids = lambda k: sorted(n["id"] if isinstance(n, tuple) is False else n[0]["id"] for n in r[k])
    assert ids("new_problems") == ["a", "fresh"] and ids("resolved") == ["b"] and ids("worse") == ["c"]
    assert ids("better") == ["e"] and ids("changed_text") == ["d"] and [o["id"] for o in r["gone"]] == ["gone"] and r["same"] == 1
    assert report.has_regression(r)


def test_no_regression_when_only_things_improved_and_gone_is_not_called_fixed():
    r = d([row("a", "fail"), row("b", "fail")], [row("a", "pass")])
    assert not report.has_regression(r) and [x[0]["id"] for x in r["resolved"]] == ["a"]
    text = report.render_diff(r, "old", "new")
    assert "## Resolved (1)" in text and "No longer reported (1)" in text and "Not the same as fixed" in text


def test_unknown_counts_as_between_pass_and_warn():
    r = d([row("a", "pass")], [row("a", "unknown")])
    assert [x[0]["id"] for x in r["new_problems"]] == ["a"]
    r2 = d([row("a", "warn")], [row("a", "unknown")])
    assert [x[0]["id"] for x in r2["better"]] == ["a"]


def test_identical_runs_say_so():
    rs = [row("a", "pass"), row("b", "warn", "q")]
    r = d(rs, rs)
    assert r["same"] == 2 and not report.has_regression(r) and "Unchanged: 2 results." in report.render_diff(r, "o", "n")


def test_save_writes_json_beside_markdown_and_last_two_orders_by_time(tmp_path):
    res = [Result("x", "X", "fail", "ev ąę", {})]
    for h in (10, 11, 12):
        report.save("md", tmp_path, datetime(2026, 11, 24, h), res)
    a, b = report.last_two(tmp_path)
    assert a.name == "raport-20261124-110000.json" and b.name == "raport-20261124-120000.json"
    assert report.load_results(b)["x"]["evidence"] == "ev ąę"
    assert report.last_two(tmp_path / "nope") is None


def test_damaged_or_foreign_json_is_a_named_error(tmp_path):
    (tmp_path / "bad.json").write_text("{not json")
    (tmp_path / "list.json").write_text(json.dumps([{"no_id": 1}]))
    for f in ("bad.json", "list.json", "missing.json"):
        with pytest.raises(ValueError, match=f):
            report.load_results(tmp_path / f)


def test_cli_diff_exit_codes(tmp_path, monkeypatch, capsys):
    from judged import __main__ as m
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    monkeypatch.setattr("sys.argv", ["judged", "diff"])
    assert m.main() == 2 and "need two saved reports" in capsys.readouterr().err
    folder = tmp_path / "judged" / "reports"
    report.save("x", folder, datetime(2026, 1, 1, 1), [Result("a", "A", "pass", "", {})])
    report.save("x", folder, datetime(2026, 1, 2, 1), [Result("a", "A", "fail", "boom", {})])
    assert m.main() == 1 and "New problems (1)" in capsys.readouterr().out
    report.save("x", folder, datetime(2026, 1, 3, 1), [Result("a", "A", "pass", "", {})])
    assert m.main() == 0 and "Resolved (1)" in capsys.readouterr().out


def test_getting_worse_alone_is_a_regression():
    assert report.has_regression(d([row("a", "warn")], [row("a", "fail")]))
    assert not report.has_regression(d([row("a", "fail")], [row("a", "warn")]))
