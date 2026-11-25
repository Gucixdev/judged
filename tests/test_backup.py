import json
import os
import time
from datetime import date, datetime, timedelta, timezone

import pytest

from judged import backup, backups
from judged.backups import Unreadable, borg, folder, restic

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
TODAY = date(2026, 11, 24)


def runs(rc=0, out=""):
    return lambda cmd, timeout=60: (rc, out)


def snaps(*specs):
    return json.dumps([{"time": t.strftime("%Y-%m-%dT%H:%M:%S.000000000Z"), "paths": p, "id": "x"} for t, p in specs])


def ids(res):
    return {r.id: r for r in res}


def test_restic_takes_the_newest_snapshot_and_its_paths():
    s = restic.latest({"repo": "r"}, runs(0, snaps((NOW - timedelta(hours=30), ["/old"]), (NOW - timedelta(hours=3), ["/home", "/etc"]))), NOW)
    assert s.when.replace(microsecond=0) == NOW - timedelta(hours=3) and s.paths == ["/home", "/etc"] and s.count == 2


def test_restic_failures_are_unreadable_not_a_pass():
    for rc, out in [(None, ""), (1, ""), (0, "not json"), (0, "{}"), (0, "[]")]:
        with pytest.raises(Unreadable):
            restic.latest({"repo": "r"}, runs(rc, out), NOW)


def test_restic_command_has_password_file_and_never_locks():
    seen = []
    restic.latest({"repo": "/r", "password_file": "~/pw"}, lambda cmd, timeout=0: (seen.append(cmd), (0, snaps((NOW, ["/"]))))[1], NOW)
    assert seen[0][:5] == ["restic", "-r", "/r", "snapshots", "--json"] and "--no-lock" in seen[0] and seen[0][-2] == "--password-file" and not seen[0][-1].startswith("~")


def test_borg_newest_archive_and_local_naive_time(monkeypatch):
    monkeypatch.setenv("TZ", "Europe/Warsaw")
    time.tzset()
    try:
        out = json.dumps({"archives": [{"name": "a", "start": "2026-11-20T10:00:00.000000"}, {"name": "b", "start": "2026-11-24T10:00:00.000000"}]})
        s = borg.latest({"repo": "r"}, runs(0, out), NOW)
        assert s.when == datetime(2026, 11, 24, 9, 0, tzinfo=timezone.utc) and s.count == 2 and s.paths is None and s.unit == "archives"
    finally:
        monkeypatch.delenv("TZ")
        time.tzset()
    for rc, out in [(None, ""), (2, ""), (0, "x"), (0, "{}"), (0, '{"archives": []}')]:
        with pytest.raises(Unreadable):
            borg.latest({"repo": "r"}, runs(rc, out), NOW)


def test_folder_newest_does_not_depend_on_the_order_the_system_lists_files(tmp_path, monkeypatch):
    new, old = tmp_path / "new", tmp_path / "old"
    new.write_text("x")
    old.write_text("x")
    os.utime(old, (1000, 1000))
    for order in (["new", "old"], ["old", "new"]):
        monkeypatch.setattr(os, "walk", lambda top, onerror=None, o=order: iter([(str(tmp_path), [], o)]))
        assert folder.latest({"repo": str(tmp_path)}, None, NOW).when.timestamp() > 1e9 + 1000


def test_folder_uses_the_newest_file_and_refuses_empty_or_missing(tmp_path):
    (tmp_path / "a").write_text("x")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b").write_text("y")
    old = time.time() - 5 * 86400
    os.utime(tmp_path / "a", (old, old))
    s = folder.latest({"repo": str(tmp_path)}, None, NOW)
    assert s.count == 2 and s.unit == "files" and abs(s.when.timestamp() - os.stat(tmp_path / "sub" / "b").st_mtime) < 1
    with pytest.raises(Unreadable):
        folder.latest({"repo": str(tmp_path / "nope")}, None, NOW)
    (tmp_path / "e").mkdir()
    with pytest.raises(Unreadable, match="no files"):
        folder.latest({"repo": str(tmp_path / "e")}, None, NOW)


def test_covered_parent_prefix_and_not_a_sibling_with_the_same_start():
    assert backups.covered(["/home"], ["/home/user/doc"]) == (["/home/user/doc"], [])
    assert backups.covered(["/home/user"], ["/home/users"]) == ([], ["/home/users"])
    assert backups.covered(["/"], ["/etc"]) == (["/etc"], [])
    assert backups.covered(["/home/"], ["/home"]) == (["/home"], [])
    assert backups.covered(None, ["/x"]) == ([], ["/x"])


def cfg(**kw):
    return {"tool": "restic", "repo": "r", "max_age_hours": 36, "must_include": [], "restore_tested": "", "restore_max_age_days": 365, **kw}


def test_latest_pass_fail_and_the_limit_itself(monkeypatch):
    def at(hours):
        return runs(0, snaps((NOW - timedelta(hours=hours), ["/home"])))
    assert ids(backup.backup_check(cfg(), TODAY, at(3), NOW))["backup.latest"].status == "pass"
    assert ids(backup.backup_check(cfg(), TODAY, at(36), NOW))["backup.latest"].status == "pass"
    r = ids(backup.backup_check(cfg(), TODAY, at(37), NOW))["backup.latest"]
    assert r.status == "fail" and "37 hours" in r.evidence and "1 snapshot is" in r.evidence
    r = ids(backup.backup_check(cfg(), TODAY, at(-5), NOW))["backup.latest"]
    assert r.status == "warn" and "future" in r.evidence


def test_coverage_fail_pass_and_unknown_for_tools_that_cannot_say():
    run = runs(0, snaps((NOW, ["/home"])))
    r = ids(backup.backup_check(cfg(must_include=["/home/user", "/etc"]), TODAY, run, NOW))["backup.coverage"]
    assert r.status == "fail" and "/etc" in r.evidence and "/home/user" not in r.evidence
    assert ids(backup.backup_check(cfg(must_include=["/home/user"]), TODAY, run, NOW))["backup.coverage"].status == "pass"
    assert "backup.coverage" not in ids(backup.backup_check(cfg(), TODAY, run, NOW))
    out = json.dumps({"archives": [{"name": "a", "start": "2026-11-24T10:00:00"}]})
    r = ids(backup.backup_check(cfg(tool="borg", must_include=["/etc"]), TODAY, runs(0, out), NOW))["backup.coverage"]
    assert r.status == "unknown" and "not checked" in r.evidence


def test_unreadable_repository_is_unknown_and_never_a_pass():
    res = ids(backup.backup_check(cfg(), TODAY, runs(1, ""), NOW))
    assert res["backup.latest"].status == "unknown" and "restic exit 1" in res["backup.latest"].evidence
    assert "backup.restore" in res                                             # the restore question is still asked


def test_config_na_and_unknown_tool():
    assert backup.backup_check(cfg(repo=""), TODAY)[0].status == "na"
    r = backup.backup_check(cfg(tool="tar"), TODAY)[0]
    assert r.status == "fail" and "known: borg, folder, restic" in r.evidence


def test_restore_test_dates():
    one = lambda **kw: backup.restore(cfg(**kw), TODAY)[0]
    assert one().status == "warn" and "never restored" in one().evidence
    assert one(restore_tested="2026-01-01").status == "pass" and "327 days" in one(restore_tested="2026-01-01").evidence
    assert one(restore_tested="2025-11-24").status == "pass"                  # exactly 365 days
    assert one(restore_tested="2025-11-23").status == "warn"
    assert one(restore_tested="yesterday").status == "fail"
    assert one(restore_tested="2027-01-01").status == "warn"
    assert one(restore_tested="2025-11-01", restore_max_age_days=1000).status == "pass"


def test_area_off_and_defaults_cover_spec():
    from judged.areas import backup_area
    assert backup_area.run({"backup": {"enabled": False}}, None) == []
    assert set(backup_area.SPEC["backup"][1]) == set(backup_area.DEFAULTS["backup"])


def test_restore_stamp_file_and_the_newer_date_wins(tmp_path):
    f = tmp_path / "restore.stamp"
    f.write_text("2026-11-01\n")
    one = lambda **kw: backup.restore(cfg(restore_tested_file=str(f), **kw), TODAY)[0]
    r = one()
    assert r.status == "pass" and r.evidence == "last restore test 23 days ago (limit 365), from restore_tested_file"
    assert "from restore_tested" in one(restore_tested="2026-11-10").evidence and "14 days ago" in one(restore_tested="2026-11-10").evidence      # newer hand date wins
    assert "23 days ago" in one(restore_tested="2026-10-01").evidence and "from restore_tested_file" in one(restore_tested="2026-10-01").evidence
    f.write_text("2024-01-01")
    assert one().status == "warn"
    f.write_text("later")
    assert one().status == "fail" and "restore_tested_file holds 'later'" in one().evidence
    f.write_text("2027-01-01")
    assert one().status == "warn" and "restore_tested_file 2027-01-01 is in the future" in one().evidence


def test_a_missing_or_empty_stamp_is_said_and_a_hand_date_still_counts(tmp_path):
    f = tmp_path / "nope.stamp"
    r = backup.restore(cfg(restore_tested_file=str(f)), TODAY)[0]
    assert r.status == "warn" and f"stamp file {f} cannot be read" in r.evidence and "never restored" in r.evidence
    f.write_text("  \n")
    assert "is empty" in backup.restore(cfg(restore_tested_file=str(f)), TODAY)[0].evidence
    r = backup.restore(cfg(restore_tested_file=str(f), restore_tested="2026-11-20"), TODAY)[0]
    assert r.status == "pass" and r.evidence.endswith("from restore_tested; stamp file " + str(f) + " is empty")


def test_only_the_first_word_of_the_stamp_counts_a_date_one_day_ahead_is_future_and_tilde_works(tmp_path, monkeypatch):
    f = tmp_path / "s"
    f.write_text("2026-11-20 verified /home/user/file.txt sha256-ok\n")
    assert backup.restore(cfg(restore_tested_file=str(f)), TODAY)[0].evidence.startswith("last restore test 4 days ago")
    f.write_text("2026-11-25")
    r = backup.restore(cfg(restore_tested_file=str(f)), TODAY)[0]
    assert r.status == "warn" and "in the future" in r.evidence
    monkeypatch.setenv("HOME", str(tmp_path))
    f.write_text("2026-11-22")
    assert "2 days ago" in backup.restore(cfg(restore_tested_file="~/s"), TODAY)[0].evidence
