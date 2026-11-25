import json

from judged import deps, lockfiles


def test_parsers():
    pl = json.dumps({"packages": {"": {"name": "app"}, "node_modules/a": {"version": "1.0.0", "resolved": "https://r/a.tgz"},
                                  "node_modules/b/node_modules/c": {"version": "2.0.0", "resolved": "https://r/c.tgz"},
                                  "node_modules/loc": {"version": "1.0.0", "link": True}, "node_modules/g": {"version": "1", "resolved": "git+ssh://x"}}})
    assert lockfiles.package_lock(pl) == [("npm", "a", "1.0.0"), ("npm", "c", "2.0.0")]
    cl = '[[package]]\nname="time"\nversion="0.1.43"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n[[package]]\nname="me"\nversion="0.1.0"\n'
    assert lockfiles.cargo_lock(cl) == [("crates.io", "time", "0.1.43")]
    co = json.dumps({"packages": [{"name": "a/b", "version": "v1.2.3", "dist": {"type": "zip"}}, {"name": "x/y", "version": "1", "dist": {"type": "path"}}]})
    assert lockfiles.composer_lock(co) == [("Packagist", "a/b", "1.2.3")]
    gm = "module m\n\ngo 1.22\n\nrequire (\n\tgithub.com/x/y v1.2.3\n\tgolang.org/x/net v0.1.0 // indirect\n)\nreplace github.com/x/y => ../y\n"
    assert ("Go", "github.com/x/y", "v1.2.3") in lockfiles.go_mod(gm) and ("Go", "golang.org/x/net", "v0.1.0") in lockfiles.go_mod(gm)
    assert lockfiles.requirements("requests==2.0.0\nflask>=1\n# c\n") == [("PyPI", "requests", "2.0.0")]
    assert lockfiles.pipfile_lock(json.dumps({"default": {"a": {"version": "==1.0"}}, "develop": {}})) == [("PyPI", "a", "1.0")]


def test_project(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {
        "node_modules/lodash": {"version": "4.17.15", "resolved": "https://r/l.tgz"},
        "node_modules/gpl": {"version": "1.0.0", "resolved": "https://r/g.tgz"}}}))
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package-lock.json").write_text("{}")             # must not be scanned
    post = lambda url, body: {"results": [{"vulns": [{"id": "GHSA-x"}]} if q["package"]["name"] == "lodash" else {} for q in body["queries"]]}
    get = lambda url: {"licenses": ["GPL-3.0-only"] if "/gpl/" in url else ["MIT"]}
    res = {r.id.rsplit(".", 1)[1]: r for r in deps.project(str(tmp_path), ["GPL"], post=post, get=get)}
    assert res["lockfiles"].evidence.startswith("1 lockfiles, 2")
    assert res["vulns"].status == "warn" and "lodash 4.17.15" in res["vulns"].evidence
    assert res["licences"].status == "fail" and "gpl (GPL)" in res["licences"].evidence


def test_offline_is_unknown_not_pass(tmp_path):
    (tmp_path / "Cargo.lock").write_text('[[package]]\nname="a"\nversion="1"\nsource="registry+x"\n')
    def down(*a, **k): raise OSError("offline")
    res = {r.id.rsplit(".", 1)[1]: r for r in deps.project(str(tmp_path), [], post=down, get=down)}
    assert res["vulns"].status == "unknown"


def test_no_lockfile_and_broken_lockfile(tmp_path):
    assert deps.project(str(tmp_path), [])[0].status == "unknown"
    (tmp_path / "Cargo.lock").write_text("not toml [[[")
    assert deps.project(str(tmp_path), [], post=lambda u, b: {"results": []}, get=lambda u: {})[0].status == "warn"
