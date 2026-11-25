import os

from judged import links


def make(tmp_path):
    r = tmp_path
    (r / "real.txt").write_text("x")
    (r / "d").mkdir()
    (r / "d" / "inner.txt").write_text("y")
    os.symlink("real.txt", r / "ok")                          # relative, works
    os.symlink("nothing.txt", r / "dead")                     # target missing
    os.symlink("loop2", r / "loop1")
    os.symlink("loop1", r / "loop2")                          # a loop
    os.symlink("/tmp/judged-test-unsafe-target", r / "tmpl")  # into /tmp, missing
    os.symlink("../real.txt", r / "d" / "up")
    os.link(r / "real.txt", r / "second_name.txt")
    return r


def ids(res):
    return {x.id.split(".", 1)[1]: x for x in res}


def test_scan_classifies_every_symlink(tmp_path):
    s = links.scan([str(make(tmp_path))])
    st = {os.path.basename(p): (state, t) for p, t, state, _ in s.links}
    assert st == {"ok": ("ok", "real.txt"), "dead": ("broken", "nothing.txt"), "loop1": ("loop", "loop2"), "loop2": ("loop", "loop1"),
                  "tmpl": ("broken", "/tmp/judged-test-unsafe-target"), "up": ("ok", "../real.txt")}


def test_broken_report_names_each_and_says_nothing_was_changed(tmp_path):
    r = ids(links.links_check({"paths": [str(make(tmp_path))]}))
    assert r["broken"].status == "warn" and "4 of 6 symlinks lead nowhere" in r["broken"].evidence
    assert "dead -> nothing.txt (target missing)" in r["broken"].evidence and "(loop)" in r["broken"].evidence and "judged only reports" in r["broken"].evidence
    assert (tmp_path / "dead").is_symlink() and os.path.lexists(tmp_path / "loop1")           # still there


def test_clean_folder_passes(tmp_path):
    (tmp_path / "a").write_text("x")
    os.symlink("a", tmp_path / "b")
    r = ids(links.links_check({"paths": [str(tmp_path)]}))
    assert [r[k].status for k in ("broken", "temp_target", "hardlinks")] == ["pass"] * 3 and "1 symlinks, every one leads to something" in r["broken"].evidence
    assert "coverage" not in r


def test_symlink_into_a_temp_folder_is_flagged_only_when_it_leaves_a_non_temp_tree(tmp_path, monkeypatch):
    hot, calm = tmp_path / "hot", tmp_path / "calm"
    hot.mkdir()
    calm.mkdir()
    monkeypatch.setattr(links, "TEMP_DIRS", (str(hot) + "/",))
    (hot / "f").write_text("x")
    os.symlink(hot / "f", calm / "out")                  # leaves a calm tree into a temp folder: flagged
    os.symlink(hot / "f", hot / "inside")                # inside the temp folder itself: normal
    r = ids(links.links_check({"paths": [str(calm), str(hot)]}))["temp_target"]
    assert r.status == "warn" and "1 symlinks point" in r.evidence and f"{calm}/out -> {hot}/f" in r.evidence and "inside" not in r.evidence
    assert ids(links.links_check({"paths": [str(hot)]}))["temp_target"].status == "pass"


def test_hardlinks_are_counted_and_a_setuid_one_warns(tmp_path):
    r = ids(links.links_check({"paths": [str(make(tmp_path))]}))["hardlinks"]
    assert r.status == "pass" and "1 files have several names" in r.evidence and "none is setuid or setgid" in r.evidence
    p = tmp_path / "su"
    p.write_text("x")
    os.link(p, tmp_path / "su2")
    os.chmod(p, 0o4755)
    w = ids(links.links_check({"paths": [str(tmp_path)]}))["hardlinks"]
    assert w.status == "warn" and "su" in w.evidence and "2 names, setuid/setgid" in w.evidence


def test_exclude_and_max_files_and_unreadable(tmp_path):
    make(tmp_path)
    ex = links.scan([str(tmp_path)], exclude=["dead", "d"])
    assert "dead" not in [os.path.basename(p) for p, *_ in ex.links] and "up" not in [os.path.basename(p) for p, *_ in ex.links]
    by_path = links.scan([str(tmp_path)], exclude=[str(tmp_path / "d")])
    assert "up" not in [os.path.basename(p) for p, *_ in by_path.links] and "dead" in [os.path.basename(p) for p, *_ in by_path.links]
    (tmp_path / "file").write_text("x")
    os.symlink("file/below", tmp_path / "under_a_file")
    assert {os.path.basename(p): s for p, _, s, _ in links.scan([str(tmp_path)]).links}["under_a_file"] == "broken"
    cut = links.scan([str(tmp_path)], max_files=3)
    assert cut.entries == 4 and "stopped after 3 entries" in cut.problems[0]
    r = ids(links.links_check({"paths": [str(tmp_path), str(tmp_path / "missing")], "max_files": 3}))
    assert r["coverage"].status == "unknown" and "cannot read" in r["coverage"].evidence and "stopped after 3" in r["coverage"].evidence


def test_no_paths_is_na_and_listing_shows_every_link(tmp_path):
    assert links.links_check({})[0].status == "na"
    lines = links.listing({"paths": [str(make(tmp_path))]})
    assert sum(l.startswith("BROKEN") for l in lines) == 2 and sum(l.startswith("LOOP") for l in lines) == 2 and sum(l.startswith("OK") for l in lines) == 2
    assert any(l.startswith("2 names:") and "real.txt" in l and "second_name.txt" in l for l in lines)


def test_a_link_that_cannot_be_followed_for_permission_is_unknown_not_broken(tmp_path):
    import pytest
    if os.geteuid() == 0:
        pytest.skip("root can follow everything")
    lock = tmp_path / "lock"
    lock.mkdir()
    (lock / "f").write_text("x")
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    os.symlink(lock / "f", scan_dir / "l")
    os.chmod(lock, 0)
    try:
        r = ids(links.links_check({"paths": [str(scan_dir)]}))
    finally:
        os.chmod(lock, 0o755)
    assert r["broken"].status == "pass" and r["coverage"].status == "unknown" and "1 symlinks could not be followed (permission)" in r["coverage"].evidence
