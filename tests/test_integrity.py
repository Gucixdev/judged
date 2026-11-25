import json
import os
import re
import subprocess
import sys
from pathlib import Path

from judged import conf, integrity


def tree(tmp):
    r = tmp / "w"
    (r / "sub").mkdir(parents=True)
    (r / "a.conf").write_text("a")
    (r / "sub" / "b.conf").write_text("b")
    (r / "skip.tmp").write_text("x")
    (r / "link").symlink_to("a.conf")
    return r


def cfg(r, **kw):
    return {"paths": [str(r)], "exclude": ["*.tmp"], "max_filesize_mb": 100, "max_files": 1000, **kw}


def test_scan_records_files_links_and_honours_exclude(tmp_path):
    r = tree(tmp_path)
    m, problems = integrity.scan([str(r)], ["*.tmp"])
    assert set(m) == {str(r / "a.conf"), str(r / "sub/b.conf"), str(r / "link")} and not problems
    assert m[str(r / "link")] == {"type": "link", "target": "a.conf", "mode": m[str(r / "link")]["mode"]}
    assert len(m[str(r / "a.conf")]["sha256"]) == 64 and m[str(r / "a.conf")]["size"] == 1


def test_scan_exclude_matches_folders_and_paths(tmp_path):
    r = tree(tmp_path)
    assert str(r / "sub/b.conf") not in integrity.scan([str(r)], ["sub"])[0]
    assert str(r / "sub/b.conf") not in integrity.scan([str(r)], [str(r / "sub/b.conf")])[0]


def test_big_files_are_recorded_but_not_hashed_and_said_so(tmp_path):
    r = tree(tmp_path)
    (r / "big").write_bytes(b"x" * (2 * 1024 * 1024))
    m, problems = integrity.scan([str(r)], [], max_filesize_mb=1)
    assert m[str(r / "big")]["sha256"] is None and m[str(r / "big")]["size"] == 2 * 1024 * 1024
    assert any("over 1 MB" in p for p in problems)
    assert m[str(r / "a.conf")]["sha256"]


def test_file_limit_stops_with_a_problem_not_silently(tmp_path):
    r = tree(tmp_path)
    m, problems = integrity.scan([str(r)], [], max_files=2)
    assert len(m) == 2 and any("stopped at 2 files" in p for p in problems)


def test_missing_and_unreadable_are_problems(tmp_path):
    r = tree(tmp_path)
    assert "not a folder" in integrity.scan([str(tmp_path / "nope")], [])[1][0]
    locked = r / "locked"
    locked.mkdir()
    (locked / "f").write_text("x")
    locked.chmod(0)
    try:
        if not os.access(locked, os.R_OK):
            assert any("locked" in p for p in integrity.scan([str(r)], [])[1])
    finally:
        locked.chmod(0o755)
    f = r / "noread"
    f.write_text("x")
    f.chmod(0)
    try:
        if not os.access(f, os.R_OK):
            assert any("noread" in p for p in integrity.scan([str(r)], [])[1])
    finally:
        f.chmod(0o644)


def test_compare_categories():
    old = {"a": {"type": "file", "size": 1, "mode": 0o644, "sha256": "1"}, "b": {"type": "file", "size": 1, "mode": 0o644, "sha256": "2"},
           "c": {"type": "file", "size": 1, "mode": 0o644, "sha256": "3"}, "l": {"type": "link", "target": "x", "mode": 0o777},
           "d": {"type": "file", "size": 1, "mode": 0o644, "sha256": "4"}}
    new = {"a": old["a"], "b": {**old["b"], "sha256": "9"}, "c": {**old["c"], "mode": 0o666}, "l": {**old["l"], "target": "y"}, "e": old["a"]}
    assert integrity.compare(old, new) == {"added": ["e"], "removed": ["d"], "changed": ["b", "l"], "mode": ["c"]}
    assert integrity.compare(old, old) == {"added": [], "removed": [], "changed": [], "mode": []}


def test_same_size_different_content_and_content_with_preserved_mtime_are_still_changes(tmp_path):
    r = tree(tmp_path)
    before, _ = integrity.scan([str(r)], [])
    st = (r / "a.conf").stat()
    (r / "a.conf").write_text("z")                                        # same size, other content
    os.utime(r / "a.conf", ns=(st.st_atime_ns, st.st_mtime_ns))             # mtime put back, as an attacker would
    after, _ = integrity.scan([str(r)], [])
    assert integrity.compare(before, after)["changed"] == [str(r / "a.conf")]


def make_baseline(r, tmp, **kw):
    bp = tmp / "base.json"
    files, _ = integrity.scan([str(r)], ["*.tmp"])
    integrity.save(bp, files, [str(r)], "2026-11-24T10:00:00Z")
    return bp


def test_check_without_paths_without_baseline_pass_and_warn(tmp_path):
    r = tree(tmp_path)
    assert integrity.integrity_check({"paths": []}, tmp_path)[0].status == "na"
    c = cfg(r, baseline=str(tmp_path / "base.json"))
    res = integrity.integrity_check(c, tmp_path)
    assert res[0].status == "unknown" and "integrity init" in res[0].evidence               # never a pass, and the baseline is not made by itself
    assert not (tmp_path / "base.json").exists()
    make_baseline(r, tmp_path)
    ok = integrity.integrity_check(c, tmp_path)
    assert [x.status for x in ok] == ["pass"] and "3 files unchanged since 2026-11-24T10:00:00Z" in ok[0].evidence
    (r / "sub/b.conf").write_text("changed")
    (r / "new").write_text("n")
    (r / "a.conf").unlink()
    w = integrity.integrity_check(c, tmp_path)[0]
    assert w.status == "warn" and "1 changed" in w.evidence and "1 added" in w.evidence and "1 removed" in w.evidence


def test_changed_scope_and_scan_problems_are_reported(tmp_path):
    r = tree(tmp_path)
    make_baseline(r, tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    res = {x.id: x for x in integrity.integrity_check({**cfg(r, baseline=str(tmp_path / "base.json")), "paths": [str(r), str(other)]}, tmp_path)}
    assert res["integrity.scope"].status == "warn"
    res = {x.id: x for x in integrity.integrity_check({**cfg(r, baseline=str(tmp_path / "base.json")), "paths": [str(r), str(tmp_path / "gone")]}, tmp_path)}
    assert res["integrity.scan"].status == "unknown" and "not a folder" in res["integrity.scan"].evidence


def test_baseline_file_is_replaced_atomically_and_remembers_what_it_replaced(tmp_path):
    bp = tmp_path / "x" / "base.json"
    integrity.save(bp, {"a": {"type": "file"}}, ["/w"], "t1")
    integrity.save(bp, {}, ["/w"], "t2", previous=integrity.load(bp))
    d = json.loads(bp.read_text())
    assert d["made"] == "t2" and d["replaces"] == {"made": "t1", "files": 1} and not list(bp.parent.glob("*.tmp"))


def test_names_are_shortened():
    assert integrity._names([str(i) for i in range(9)]) == "0, 1, 2, 3, 4, 5 and 3 more"


def run(args, tmp, r, **kw):
    text = re.sub(r"^integrity .*$", f"integrity enabled=1 paths={r} exclude=*.tmp max_filesize_mb=100 max_files=1000 baseline={tmp / 'b.json'}", conf.template(), flags=re.M)
    (tmp / "j.conf").write_text(text)
    env = {"PYTHONPATH": str(Path(__file__).parent.parent), "PATH": "/usr/bin:/bin", "XDG_STATE_HOME": str(tmp / "st")}
    return subprocess.run([sys.executable, "-m", "judged", "integrity", *args, "-c", str(tmp / "j.conf")], capture_output=True, text=True, env=env, timeout=60)


def test_cli_init_refuses_to_overwrite_accept_needs_a_baseline_and_show_reports(tmp_path):
    r = tree(tmp_path)
    assert run([], tmp_path, r).returncode == 2
    assert run(["accept"], tmp_path, r).returncode == 2
    assert "no baseline to replace" in run(["accept"], tmp_path, r).stderr
    a = run(["init"], tmp_path, r)
    assert a.returncode == 0 and "3 files" in a.stdout
    b = run(["init"], tmp_path, r)
    assert b.returncode == 2 and "already exists" in b.stderr
    (r / "a.conf").write_text("zz")
    assert "1 changed" in run(["show"], tmp_path, r).stdout
    assert run(["accept"], tmp_path, r).returncode == 0
    assert "unchanged" in run(["show"], tmp_path, r).stdout
