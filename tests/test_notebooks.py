import json
from pathlib import Path

NB = Path(__file__).resolve().parent.parent / "notebooks"


def cells(name, edit=lambda s: s):
    nb = json.loads((NB / name).read_text())
    return edit("\n".join("".join(c["source"]) for c in nb["cells"] if c["cell_type"] == "code"))


def run(src, **inject):
    ns = {}
    exec(compile(src, "notebook", "exec"), ns)
    return ns


def test_costs_notebook_runs_offline_and_estimates(capsys, monkeypatch):
    monkeypatch.chdir(NB)
    ns = run(cells("costs.ipynb", lambda s: s.replace("OFFLINE = False", "OFFLINE = True")))
    out = capsys.readouterr().out
    assert "rates: none" in out and "WARNING: no USD to EUR rate" in out
    rows = {r[0]: r[2] for r in ns["estimate"]()}
    assert rows["Expiry tracking"] == 0.1 * 4.0 * (300 + 5 * 40)
    assert rows["Contract notice dates"] == 12000 * 0.05
    assert rows["Paperwork: evidence for audits and insurers"] == 40 * 0.5 * 45


def test_conversion_and_windows_estimate(monkeypatch):
    monkeypatch.chdir(NB)
    ns = run(cells("costs.ipynb", lambda s: s.replace("OFFLINE = False", "OFFLINE = True")))
    rates = {"EUR": 1.0, "USD": 2.0}
    assert ns["convert"](10, "USD", "EUR", rates) == 5 and ns["convert"](10, "EUR", "EUR", None) == 10 and ns["convert"](1, "USD", "EUR", None) is None
    ns["RATES"].update(rates) if ns["RATES"] else ns.__setitem__("RATES", rates)
    m = {**ns["MINE"], "windows10_devices": 100, "breach_cost": 1000.0}
    got = {r[0]: r[2] for r in ns["estimate"](m)}
    assert got["Windows 10 end of life"] == 100 * 61 / 2
    assert got["Known exploited vulnerabilities, secrets, hardening"] == 1000.0 * 0.03 * 0.10


def test_notebook_is_valid_and_has_no_stored_output():
    nb = json.loads((NB / "costs.ipynb").read_text())
    assert nb["nbformat"] == 4
    assert all(c.get("outputs") == [] for c in nb["cells"] if c["cell_type"] == "code")
