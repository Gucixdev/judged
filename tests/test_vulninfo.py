import json

import pytest

from judged import deps, vulninfo

# Well-known vectors with the scores NVD publishes for them.
KNOWN = [("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8), ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
         ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5), ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
         ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8), ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
         ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2), ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 6.2),
         ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8), ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
         ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0)]


@pytest.mark.parametrize("vec,score", KNOWN)
def test_cvss3_scores_match_the_published_ones(vec, score):
    assert vulninfo.cvss3(vec) == score


def test_cvss3_refuses_what_it_cannot_score():
    assert vulninfo.cvss3("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
    assert vulninfo.cvss3("CVSS:3.1/AV:N/AC:L") is None and vulninfo.cvss3("") is None and vulninfo.cvss3("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None


def test_roundup_is_the_3_1_rule():
    assert vulninfo.roundup(4.0) == 4.0 and vulninfo.roundup(4.000001) == 4.0 and vulninfo.roundup(4.00002) == 4.1 and vulninfo.roundup(7.02) == 7.1 and vulninfo.roundup(7.0) == 7.0


def test_bands_at_their_edges():
    assert [vulninfo.band(x) for x in (0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10)] == ["NONE", "LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"]


# the three shapes seen in real OSV records (GHSA-35jh-r3h4-6jhm, RUSTSEC-2020-0071, PYSEC-2021-421)
GHSA = {"id": "GHSA-35jh-r3h4-6jhm", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}], "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": "lodash", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]},
                     {"package": {"name": "lodash-es", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]}]}
RUST = {"id": "RUSTSEC-2020-0071", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
        "affected": [{"package": {"name": "time", "ecosystem": "crates.io"}, "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "0.0.0-0"}, {"fixed": "0.2.0"}, {"introduced": "0.2.1-0"}, {"fixed": "0.2.1"}, {"introduced": "0.2.7-0"}, {"fixed": "0.2.23"}]}]}]}
PYSEC = {"id": "PYSEC-2021-421", "affected": [{"package": {"name": "babel", "ecosystem": "PyPI"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.9.1"}]}]}]}
V4 = {"id": "X-1", "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]}


def test_severity_prefers_the_database_label_then_the_vector_then_says_unrated():
    assert vulninfo.severity(GHSA) == ("HIGH", 7.2) and vulninfo.severity(RUST) == ("MEDIUM", 6.2) and vulninfo.severity(PYSEC) == ("UNRATED", None)
    assert vulninfo.severity(V4) == ("UNRATED (CVSS v4)", None) and vulninfo.severity({}) == ("UNRATED", None)
    g = {"database_specific": {"severity": "MODERATE"}, "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    assert vulninfo.severity(g) == ("MEDIUM", 9.8)                                  # GitHub's own judgement wins over the vector
    assert vulninfo.severity({"database_specific": {"severity": "weird"}, "severity": []}) == ("UNRATED", None)


def test_fixed_hint_picks_the_lowest_fix_above_the_installed_version_for_exactly_this_package():
    assert vulninfo.fixed_hint(GHSA, "npm", "lodash", "4.17.20") == "4.17.21"
    assert vulninfo.fixed_hint(GHSA, "npm", "lodash", "4.17.21") is None             # already at the fix
    assert vulninfo.fixed_hint(GHSA, "npm", "lodash-es", "4.17.0") == "9.9.9"        # the other package's entry is not mixed in
    assert vulninfo.fixed_hint(RUST, "crates.io", "time", "0.2.5") == "0.2.23" and vulninfo.fixed_hint(RUST, "crates.io", "time", "0.1.0") == "0.2.0"
    assert vulninfo.fixed_hint(RUST, "crates.io", "time", "0.2.23") is None
    assert vulninfo.fixed_hint(PYSEC, "PyPI", "babel", "2.9.0") == "2.9.1" and vulninfo.fixed_hint(PYSEC, "PyPI", "babel", "2.10.0") is None
    assert vulninfo.fixed_hint(GHSA, "PyPI", "lodash", "1") is None and vulninfo.fixed_hint({}, "npm", "x", "1") is None
    assert vulninfo.fixed_hint({"affected": [{"package": {"name": "x", "ecosystem": "npm"}, "ranges": [{"events": [{"introduced": "0"}]}]}]}, "npm", "x", "1") is None
    assert vulninfo.fixed_hint(GHSA, "npm", "lodash", "4.9") == "4.17.21" and vulninfo.fixed_hint(GHSA, "npm", "lodash", "10.0") is None   # numbers, not text order


def test_details_fetches_each_id_once_respects_the_limit_and_survives_failures():
    calls = []
    def get(url):
        calls.append(url)
        i = url.rsplit("/", 1)[1]
        if i == "BOOM":
            raise OSError("down")
        return {"GHSA-35jh-r3h4-6jhm": GHSA, "RUSTSEC-2020-0071": RUST}.get(i, {"unexpected": True})
    hit = {("npm", "lodash", "4.17.20"): ["GHSA-35jh-r3h4-6jhm", "BOOM"], ("npm", "lodash-es", "4.0.0"): ["GHSA-35jh-r3h4-6jhm", "WEIRD"]}
    d = vulninfo.details(hit, get)
    assert d[("npm", "lodash", "4.17.20")] == [("GHSA-35jh-r3h4-6jhm", "HIGH", 7.2, "4.17.21"), ("BOOM", "UNRATED", None, None)]
    assert d[("npm", "lodash-es", "4.0.0")] == [("GHSA-35jh-r3h4-6jhm", "HIGH", 7.2, "9.9.9"), ("WEIRD", "UNRATED", None, None)]
    assert calls == [f"https://api.osv.dev/v1/vulns/{i}" for i in ("GHSA-35jh-r3h4-6jhm", "BOOM", "WEIRD")]
    calls.clear()
    d = vulninfo.details({("npm", "a", "1"): ["RUSTSEC-2020-0071", "GHSA-35jh-r3h4-6jhm", "BOOM"]}, get, limit=2)
    assert [r[1] for r in d[("npm", "a", "1")]] == ["MEDIUM", "HIGH", "UNRATED"] and len(calls) == 2


def make_project(tmp_path, pkgs):
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}, **{f"node_modules/{n}": {"version": v, "resolved": f"https://registry.npmjs.org/{n}/-/{n}-{v}.tgz"} for n, v in pkgs}}}))


def test_project_result_names_the_worst_id_its_severity_and_the_fix(tmp_path):
    make_project(tmp_path, [("lodash", "4.17.20"), ("left-pad", "1.3.0"), ("minimist", "1.0.0")])
    osv = {"lodash": ["GHSA-35jh-r3h4-6jhm"], "left-pad": [], "minimist": ["PYSEC-2021-421", "RUSTSEC-2020-0071"]}
    post = lambda url, body: {"results": [{"vulns": [{"id": i} for i in osv[q["package"]["name"]]]} for q in body["queries"]]}
    recs = {"GHSA-35jh-r3h4-6jhm": GHSA, "PYSEC-2021-421": PYSEC, "RUSTSEC-2020-0071": RUST}
    get = lambda url: recs[url.rsplit("/", 1)[1]] if "osv.dev" in url else {"licenses": ["MIT"]}
    r = {x.id.split(".")[-1]: x for x in deps.project(str(tmp_path), [], post=post, get=get)}["vulns"]
    assert r.status == "fail"
    assert r.evidence == ("2 of 3 packages (1 high or critical): lodash 4.17.20 (GHSA-35jh-r3h4-6jhm high 7.2; fixed in 4.17.21, loose version order); "
                          "minimist 1.0.0 (RUSTSEC-2020-0071 medium 6.2, +1 more; no fixed version listed above yours)")


def test_only_medium_and_low_is_a_warning_and_a_clean_project_a_pass(tmp_path):
    make_project(tmp_path, [("a", "1.0.0")])
    one = lambda ids: (lambda url, body: {"results": [{"vulns": [{"id": i} for i in ids]} for _ in body["queries"]]})
    get = lambda url: RUST if "osv.dev" in url else {"licenses": ["MIT"]}
    assert {x.id.split(".")[-1]: x for x in deps.project(str(tmp_path), [], post=one(["RUSTSEC-2020-0071"]), get=get)}["vulns"].status == "warn"
    assert {x.id.split(".")[-1]: x for x in deps.project(str(tmp_path), [], post=one([]), get=get)}["vulns"].status == "pass"
    down = lambda url: (_ for _ in ()).throw(OSError("offline")) if "osv.dev" in url else {"licenses": ["MIT"]}
    r = {x.id.split(".")[-1]: x for x in deps.project(str(tmp_path), [], post=one(["X"]), get=down)}["vulns"]
    assert r.status == "warn" and "x unrated" not in r.evidence and "(X unrated; no fixed version listed above yours)" in r.evidence


def test_severity_lookup_limit_is_said_in_the_result(tmp_path):
    make_project(tmp_path, [("a", "1.0.0")])
    post = lambda url, body: {"results": [{"vulns": [{"id": f"ID-{i}"} for i in range(3)]} for _ in body["queries"]]}
    r = {x.id.split(".")[-1]: x for x in deps.project(str(tmp_path), [], post=post, get=lambda u: PYSEC if "osv.dev" in u else {}, max_vuln_details=2)}["vulns"]
    assert "severity looked up for the first 2 ids only" in r.evidence


def test_a_vector_without_the_cvss_prefix_or_of_another_version_is_not_scored():
    assert vulninfo.cvss3("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None and vulninfo.cvss3("CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None


def test_worst_package_comes_first_and_more_than_five_are_counted_not_listed(tmp_path):
    names = ["a-medium", "b-low", "c-x", "d-x", "e-x", "f-x", "z-high"]
    make_project(tmp_path, [(n, "1.0.0") for n in names])
    recs = {"M": RUST, "H": GHSA, "L": {"id": "L", "severity": [], "database_specific": {"severity": "LOW"}}}
    pick = {"a-medium": "M", "z-high": "H"}
    post = lambda url, body: {"results": [{"vulns": [{"id": pick.get(q["package"]["name"], "L")}]} for q in body["queries"]]}
    get = lambda url: recs[url.rsplit("/", 1)[1]] if "osv.dev" in url else {"licenses": ["MIT"]}
    r = {x.id.split(".")[-1]: x for x in deps.project(str(tmp_path), [], post=post, get=get)}["vulns"]
    assert r.evidence.startswith("7 of 7 packages (1 high or critical): z-high 1.0.0 (H high 7.2")
    assert r.evidence.index("z-high") < r.evidence.index("a-medium") < r.evidence.index("b-low") and r.evidence.count("; (+") == 1 and "; (+2 more)" in r.evidence
    assert "e-x" not in r.evidence and "f-x" not in r.evidence and "d-x" in r.evidence
