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


def test_pdf_report_is_written_when_matplotlib_is_there(monkeypatch, report_dir):
    pytest.importorskip("matplotlib")
    monkeypatch.chdir(NB)
    run(cells("costs.ipynb", lambda s: s.replace("OFFLINE = False", "OFFLINE = True")))
    assert (report_dir / "costs.pdf").read_bytes().startswith(b"%PDF")


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


def test_conversion_and_survey_table(monkeypatch):
    ns = offline(monkeypatch)
    rates = {"EUR": 1.0, "USD": 2.0}
    assert ns["convert"](10, "USD", "EUR", rates) == 5 and ns["convert"](10, "EUR", "EUR", None) == 10 and ns["convert"](1, "USD", "EUR", None) is None
    cur, got = ns["survey_rows"]()
    assert cur == "GBP" and got["all businesses"] == [0, 200, 1500, 4000]
    for table in ("all_answers", "only_above_zero"):
        for vals in ns["SURVEY"][table].values():
            assert len(vals) == len(ns["SURVEY"]["levels"]) and vals == sorted(vals)


def test_the_chart_slices_make_one_whole(monkeypatch):
    slices = offline(monkeypatch)["survey_slices"]()
    assert [round(s[1], 2) for s in slices] == [57, 32.25, 6.45, 2.15, 2.15] and sum(s[1] for s in slices) == pytest.approx(100)
    assert "GBP 4,000" in slices[-1][0]


def test_why_judged_says_whose_the_percentage_is(monkeypatch, capsys):
    why = offline(monkeypatch)["WHY"]
    assert f"{why['percent']}%" in why["headline"] and "Cyber Essentials certification" in why["headline"] and "judged" not in why["headline"]
    assert "not about judged" in why["caveat"] and why["quote"].startswith(f"{why['percent']}%")
    assert why["caveat"].split()[0] in capsys.readouterr().out


def test_why_judged_five_areas_are_really_mapped_in_the_code():
    mapped = {c for name in dir(controls) if name.startswith("M_") for c in getattr(controls, name).get("ce", [])}
    assert {"firewalls", "secure-config", "user-access", "malware", "updates"} <= mapped


def test_notebook_is_valid_and_has_no_stored_output():
    nb = json.loads((NB / "costs.ipynb").read_text())
    assert nb["nbformat"] == 4
    assert all(c.get("outputs") == [] for c in nb["cells"] if c["cell_type"] == "code")
