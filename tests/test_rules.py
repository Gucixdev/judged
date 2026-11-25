import sys
from types import SimpleNamespace

import pytest

from judged import conf, rules


def run_cmd(code, out=""):
    return rules.run({"name": "Backup is recent", "cmd": [sys.executable, "-c", f"print({out!r}); raise SystemExit({code})"],
                      "maps": {"iso27001": ["A.8.13"]}})


def test_exit_codes_map_to_statuses():
    assert run_cmd(0, "fresh").status == "pass" and run_cmd(0, "fresh").evidence == "fresh"
    assert run_cmd(1, "stale").status == "fail"
    assert run_cmd(2, "old").status == "warn"
    r = run_cmd(7, "weird")
    assert r.status == "unknown" and "exit 7" in r.evidence
    assert run_cmd(0).maps == {"iso27001": ["A.8.13"]} and run_cmd(0).id == "rule.backup-is-recent"


def test_missing_program_and_timeout_are_unknown():
    assert rules.run({"name": "x", "cmd": ["/nonexistent/prog"]}).status == "unknown"
    assert rules.run({"name": "x", "cmd": [sys.executable, "-c", "import time; time.sleep(5)"], "timeout": 1}).status == "unknown"


def test_check_line_and_include(tmp_path):
    (tmp_path / "rules").mkdir()
    (tmp_path / "rules" / "backup.rules").write_text('check "Backup is recent" cmd="test -d /" maps=ce:updates,iso27001:A.8.13 warn_exit=3\n'
                                                      'control ce my-extra "My extra control"\n')
    (tmp_path / "judged.conf").write_text("include rules/*.rules\ngpg\n")
    cfg = conf.load(tmp_path / "judged.conf")
    assert cfg["checks"][0] == {"name": "Backup is recent", "cmd": ["test", "-d", "/"], "maps": {"ce": ["updates"], "iso27001": ["A.8.13"]}, "warn_exit": 3}
    assert cfg["frameworks"]["ce"]["controls"]["my-extra"] == "My extra control"
    assert cfg["item"] == [{"kind": "gpg"}]


def test_include_errors(tmp_path):
    (tmp_path / "a.conf").write_text("include nothing/*.rules\n")
    with pytest.raises(conf.ConfError, match="matches no file"):
        conf.load(tmp_path / "a.conf")
    (tmp_path / "loop.conf").write_text("include loop.conf\n")
    with pytest.raises(conf.ConfError, match="deeper than 5"):
        conf.load(tmp_path / "loop.conf")
    with pytest.raises(conf.ConfError, match="needs cmd"):
        conf.parse('check "x"')
    with pytest.raises(conf.ConfError, match="framework:control"):
        conf.parse('check "x" cmd=true maps=oops')
