import sys
from datetime import date

import pytest

from judged import areas, conf

CTX = areas.Ctx(date(2026, 11, 24), None)


@pytest.fixture
def drop(tmp_path, monkeypatch):
    """Put a new area file next to the real ones, the way a person adds one."""
    monkeypatch.setattr(areas, "__path__", list(areas.__path__) + [str(tmp_path)])
    added = []

    def put(name, body):
        (tmp_path / f"{name}.py").write_text(body)
        added.append(f"judged.areas.{name}")
    yield put
    for m in added:
        sys.modules.pop(m, None)


GOOD = '''
from judged.controls import Result
NAME, ORDER = "demo", 1
SPEC = {"demoarea": ((), {"limit": "int", "paths": "list"}, "section")}
def run(cfg, ctx):
    d = cfg.get("demoarea", {})
    return [Result("demo.one", "Demo", "pass", f"limit {d.get('limit')} on {ctx.today}", {})]
'''


def test_new_area_file_is_found_runs_in_order_and_adds_its_config_lines(drop):
    drop("demo", GOOD)
    cfg = conf.parse("demoarea limit=7 paths=/a,/b\n")
    assert cfg["demoarea"] == {"limit": 7, "paths": ["/a", "/b"]}          # no edit in conf.py was needed
    out = areas.run_all(cfg, CTX)
    assert out[0].id == "demo.one" and out[0].evidence == "limit 7 on 2026-11-24"      # ORDER = 1 runs before the built-in ones


def test_unknown_directive_still_fails_without_the_area(drop):
    with pytest.raises(conf.ConfError, match="unknown directive 'demoarea'"):
        conf.parse("demoarea limit=7\n")


def test_a_crashing_area_becomes_one_unknown_and_the_rest_still_run(drop):
    drop("boom", 'NAME, ORDER = "boom", 2\ndef run(cfg, ctx):\n    raise RuntimeError("disk gone")\n')
    drop("after", 'from judged.controls import Result\nNAME, ORDER = "after", 3\ndef run(cfg, ctx):\n    return [Result("after.ok", "After", "pass", "ran", {})]\n')
    out = {r.id: r for r in areas.run_all({}, CTX)}
    assert out["area.boom"].status == "unknown" and "RuntimeError: disk gone" in out["area.boom"].evidence
    assert out["after.ok"].status == "pass"


def test_file_without_run_is_not_an_area_and_every_builtin_is_found():
    names = [m.__name__.rsplit(".", 1)[-1] for m in areas.discover()]
    assert names[:2] == ["feeds_area", "host"] and "codestd_area" in names and "malware_area" in names and "software" in names and names == sorted(names, key=lambda n: [m.ORDER for m in areas.discover() if m.__name__.endswith("." + n)][0])
    assert all(hasattr(m, "NAME") and hasattr(m, "ORDER") for m in areas.discover())
