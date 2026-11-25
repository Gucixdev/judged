import json
import urllib.error

import pytest

from judged import deps, licsources
from judged.licsources import depsdev, packagist

# The shape of https://repo.packagist.org/p2/monolog/monolog.json (checked live 2026-11-24): minified, only the first entry sets `license`.
DOC = {"minified": "composer/2.0", "packages": {"acme/lib": [
    {"name": "acme/lib", "version": "3.0.0", "version_normalized": "3.0.0.0", "license": ["MIT"]},
    {"version": "2.1.0", "version_normalized": "2.1.0.0"},
    {"version": "v2.0.0", "version_normalized": "2.0.0.0", "license": ["GPL-3.0-or-later", "Apache-2.0"]},
    {"version": "1.5.0", "version_normalized": "1.5.0.0"},
    {"version": "1.0.0", "version_normalized": "1.0.0.0", "license": "__unset"},
    {"version": "dev-main", "version_normalized": "dev-main"}]}}


def get_doc(url):
    get_doc.urls.append(url)
    return DOC


get_doc.urls = []


def lic(version, name="acme/lib"):
    return packagist.licence("Packagist", name, version, get_doc)


def test_inherited_licences_are_filled_in_and_overrides_win():
    assert lic("3.0.0") == "MIT" and lic("2.1.0") == "MIT"                       # inherited from the entry above
    assert lic("2.0.0") == "GPL-3.0-or-later AND Apache-2.0" and lic("1.5.0") == "GPL-3.0-or-later AND Apache-2.0"
    assert lic("1.0.0") == "" and lic("dev-main") == ""                         # __unset: the registry lists none, and it stays unset below
    assert lic("9.9.9") is None                                                  # version not in the document: unknown, not a guess


def test_version_matches_with_or_without_v_and_by_normalized_form():
    assert lic("v3.0.0") == "MIT" and lic("2.0.0") == lic("v2.0.0") and lic("3.0.0.0") == "MIT"


def test_request_url_is_lowercase_and_keeps_the_slash():
    get_doc.urls.clear()
    lic("3.0.0", "Acme/Lib")
    assert get_doc.urls == ["https://repo.packagist.org/p2/acme/lib.json"]


def test_not_on_packagist_is_unknown_other_errors_propagate():
    def gone(url):
        raise urllib.error.HTTPError(url, 404, "nf", {}, None)
    assert packagist.licence("Packagist", "x/y", "1", gone) is None
    def boom(url):
        raise urllib.error.HTTPError(url, 500, "err", {}, None)
    with pytest.raises(OSError):
        packagist.licence("Packagist", "x/y", "1", boom)
    assert packagist.licence("Packagist", "x/y", "1", lambda u: {"packages": {}}) is None


def test_expand_only_changes_the_field_it_is_asked_for():
    assert packagist.expand([{"version": "2", "x": 1}, {"version": "1", "license": ["MIT"]}], "license") == [("2", "", None), ("1", "", ["MIT"])]
    assert packagist.expand([{"version": "2"}, {"version": "1", "x": ["a"]}], "x") == [("2", "", None), ("1", "", ["a"])]


def test_sources_are_discovered_and_do_not_overlap():
    assert licsources.find("Packagist") is packagist and licsources.find("npm") is depsdev and licsources.find("Hex") is None
    every = [e for m in licsources.discover() for e in m.ECOSYSTEMS]
    assert len(every) == len(set(every)) and licsources.covered() == set(every) >= {"Packagist", "npm", "PyPI", "Maven", "NuGet", "RubyGems", "Go", "crates.io"}


def test_deps_licence_of_routes_php_to_packagist_and_the_rest_to_depsdev():
    seen = []
    def get(url):
        seen.append(url)
        return DOC if "packagist" in url else {"licenses": ["ISC"]}
    assert deps.licence_of(("Packagist", "acme/lib", "2.1.0"), get) == "MIT" and deps.licence_of(("npm", "x", "1"), get) == "ISC"
    assert seen[0].startswith("https://repo.packagist.org/") and seen[1].startswith("https://api.deps.dev/")


def test_a_composer_project_gets_licences_through_the_whole_audit(tmp_path):
    (tmp_path / "composer.lock").write_text(json.dumps({"packages": [{"name": "acme/lib", "version": "v2.0.0", "dist": {"type": "zip"}},
                                                                    {"name": "acme/free", "version": "3.0.0", "dist": {"type": "zip"}}], "packages-dev": []}))
    def get(url):
        return DOC if url.endswith("acme/lib.json") else {"packages": {"acme/free": [{"version": "3.0.0", "license": ["MIT"]}]}}
    post = lambda url, body: {"results": [{} for _ in body["queries"]]}
    res = {r.id.split(".")[-1]: r for r in deps.project(str(tmp_path), [], post=post, get=get)}
    assert res["licences"].status == "warn" and res["licences"].evidence == "review: acme/lib (GPL). 1 permissive, 1 strong-copyleft"
    res = {r.id.split(".")[-1]: r for r in deps.project(str(tmp_path), ["GPL"], post=post, get=get)}
    assert res["licences"].status == "fail" and res["licences"].evidence.startswith("denied: acme/lib (GPL).")
