import json
from datetime import date
from pathlib import Path

import pytest

from judged import controls

NB = Path(__file__).resolve().parent.parent / "notebooks"


def cells(name, edit=lambda s: s):
    nb = json.loads((NB / name).read_text())
    return edit("\n".join("".join(c["source"]) for c in nb["cells"] if c["cell_type"] == "code"))


def run(src, **inject):
    ns = {}
    exec(compile(src, "notebook", "exec"), ns)
    return ns


@pytest.fixture(autouse=True)
def report_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("JUDGED_REPORT_DIR", str(tmp_path))   # the PDF must not land in the repo
    monkeypatch.setenv("MPLBACKEND", "Agg")
    return tmp_path


def test_pdf_has_six_slides_and_one_more_with_records(monkeypatch, report_dir):
    pytest.importorskip("matplotlib")
    ns = offline(monkeypatch)
    assert ns["PAGES"] == 6 and (report_dir / "costs.pdf").read_bytes().startswith(b"%PDF")
    assert all(page.axes for page in ns["slides"]())            # Jupyter shows nothing for a figure without axes
    ns["RECORDS_SINCE"] = "2024-01-01"
    assert ns["report"](report_dir / "again.pdf") == 7
    ns["INCIDENTS"] = [{"date": "2025-03-02", "check": "expiry", "what": "cert " * 30, "cost": 300.0, "proof": "ticket 7"}] * 11
    assert ns["report"](report_dir / "many.pdf") == 8          # ten records fit on one slide


def offline(monkeypatch):
    monkeypatch.chdir(NB)
    return run(cells("costs.ipynb", lambda s: s.replace("OFFLINE = False", "OFFLINE = True")))


def test_costs_notebook_gives_no_number_without_records(capsys, monkeypatch):
    ns = offline(monkeypatch)
    out = capsys.readouterr().out
    assert "rates: none" in out and "NO NUMBER YET" in out
    assert ns["MEASURED"] is None and ns["RECORDS_SINCE"] is None and ns["INCIDENTS"] == [] and "estimate" not in ns


def test_records_are_added_up_and_a_year_is_needed_for_a_yearly_figure(monkeypatch):
    ns = offline(monkeypatch)
    measured, today = ns["measured"], date(2026, 1, 1)
    one = {"date": "2025-03-02", "check": "expiry", "what": "cert", "cost": 300.0, "proof": "ticket 7"}
    two = {**one, "check": "contract", "cost": 900.0}
    m = measured([one, two, one], "2024-01-01", today)
    assert m["total"] == 1500 and m["by_check"] == {"expiry": 600, "contract": 900} and m["per_year"] == pytest.approx(1500 / (731 / 365.25))
    assert measured([one], "2025-03-01", today)["per_year"] is None
    assert measured([], "2024-01-01", today)["per_year"] == 0


@pytest.mark.parametrize("bad, why", [({"proof": " "}, "no proof"), ({"check": "luck"}, "check must be"), ({"cost": -1.0}, "cost must"),
                                      ({"date": "2023-01-01"}, "outside"), ({"date": "2027-01-01"}, "outside")])
def test_a_record_that_cannot_be_counted_is_refused(monkeypatch, bad, why):
    ns = offline(monkeypatch)
    one = {"date": "2025-03-02", "check": "expiry", "what": "cert", "cost": 300.0, "proof": "ticket 7", **bad}
    with pytest.raises(ValueError, match=why):
        ns["measured"]([one], "2024-01-01", date(2026, 1, 1))
    with pytest.raises(ValueError, match="RECORDS_SINCE"):
        ns["measured"]([one], None)


def test_conversion_and_the_chart_rows(monkeypatch):
    ns = offline(monkeypatch)
    rates = {"EUR": 1.0, "USD": 2.0}
    assert ns["convert"](10, "USD", "EUR", rates) == 5 and ns["convert"](10, "EUR", "EUR", None) == 10 and ns["convert"](1, "USD", "EUR", None) is None
    rows = ns["miss_rows"]()
    assert rows[0][2:5] == (137 * 60, 427 * 60, "USD")          # no rates offline: the source currency is shown, not relabelled
    for head, small, lo, hi, cur, legal in rows:
        assert 0 < lo <= hi and legal == ("MAXIMUM" in small)    # a ceiling must say so in its own row
    assert "NOT a small-firm figure" in rows[3][1]
    assert [ns["short"](v) for v in (8220, 10_000_000, 1_395_603)] == ["8.2 k", "10 M", "1.4 M"]


def test_every_number_has_a_source_and_a_text_to_look_for(monkeypatch):
    ns = offline(monkeypatch)
    entries = dict(ns["sources"]())
    assert {m[0] for m in ns["MISSES"]} <= set(entries) and {g[3] for g in ns["GAINS"]} <= set(entries)
    assert all(e["url"].startswith("https://") and e["quote"] and e["source"] for e in entries.values())


def test_source_check_tells_confirmed_gone_and_unloadable_apart(monkeypatch):
    verify = offline(monkeypatch)["verify"]

    def fetch(url):
        if url == "down":
            raise OSError("reset")
        return "<p>cost <b>$137</b> to $427 &amp; more</p>"

    got = verify([("a", {"url": "x", "quote": "$137 to $427 & more"}), ("b", {"url": "x", "quote": "$999"}), ("c", {"url": "down", "quote": "x"})], fetch)
    assert got == {"a": "confirmed", "b": "NOT FOUND", "c": "open by hand"}


def test_the_percentage_says_whose_it_is_and_nothing_judged_lacks_is_sold(monkeypatch):
    ns = offline(monkeypatch)
    claims = next(g for g in ns["GAINS"] if g[3] == "claims")
    assert "with Cyber Essentials" in claims[2] and "not about judged" in claims[2]
    assert "does not certify" in ns["GAIN_BRIDGE"]
    assert "Windows 10" not in (NB / "costs.ipynb").read_text() + (NB / "costdata.json").read_text()


def test_why_judged_five_areas_are_really_mapped_in_the_code():
    mapped = {c for name in dir(controls) if name.startswith("M_") for c in getattr(controls, name).get("ce", [])}
    assert {"firewalls", "secure-config", "user-access", "malware", "updates"} <= mapped


def test_notebook_is_valid_and_has_no_stored_output():
    nb = json.loads((NB / "costs.ipynb").read_text())
    assert nb["nbformat"] == 4
    assert all(c.get("outputs") == [] for c in nb["cells"] if c["cell_type"] == "code")
