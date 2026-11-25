from datetime import date

from judged import conf, deps, waivers

TODAY = date(2026, 11, 24)


def w(id="GHSA-1", expires=date(2027, 1, 1), owner="anna", reason="not reachable", package=None):
    d = {"id": id, "expires": expires, "owner": owner, "reason": reason}
    if package:
        d["package"] = package
    return d


HIT = {("npm", "lodash", "4.17.0"): ["GHSA-1", "GHSA-2"], ("npm", "minimist", "1.0.0"): ["GHSA-3"]}


def test_split_needs_owner_reason_and_future_date():
    act, prob = waivers.split([w(), w("B", owner=""), w("C", reason=""), w("D", expires=date(2026, 11, 23)), w("E", expires=TODAY)], TODAY)
    assert [a["id"] for a in act] == ["GHSA-1", "E"]                 # a waiver ending today is still valid
    assert len(prob) == 3 and "needs owner= and reason=" in prob[0] and "expired on 2026-11-23" in prob[2]


def test_apply_removes_only_waived_ids_and_respects_package():
    left, done = waivers.apply(HIT, [w("GHSA-1"), w("GHSA-3", package="other")], TODAY)
    assert left == {("npm", "lodash", "4.17.0"): ["GHSA-2"], ("npm", "minimist", "1.0.0"): ["GHSA-3"]}   # wrong package: not waived
    assert done == ["GHSA-1 in lodash until 2027-01-01 by anna"]


def test_seen_and_ending_soon():
    seen = set()
    _, done = waivers.apply(HIT, [w("GHSA-3", expires=date(2026, 12, 1), package="minimist")], TODAY, seen)
    assert seen == {("GHSA-3", "minimist")} and "(ends soon)" in done[0]


def test_summary_pass_warn_unused_and_empty():
    assert waivers.summary([], TODAY, set()) == []
    ok = waivers.summary([w()], TODAY, {("GHSA-1", None)})[0]
    assert ok.status == "pass" and "next ends 2027-01-01" in ok.evidence
    un = waivers.summary([w("GHSA-9")], TODAY, set())[0]
    assert un.status == "warn" and "GHSA-9" in un.evidence and "remove it" in un.evidence
    ex = waivers.summary([w(expires=date(2026, 1, 1))], TODAY, set())[0]
    assert ex.status == "warn" and "expired" in ex.evidence


def test_conf_line_with_quoted_reason():
    cfg = conf.parse('waive GHSA-xxxx-1 2026-12-31 owner=anna reason="no fix yet, not reachable" package=lodash\n', "t.conf")
    e = cfg["item"][0]
    assert e["kind"] == "waive" and e["reason"] == "no fix yet, not reachable" and e["package"] == "lodash" and e["expires"] == date(2026, 12, 31)


def test_deps_project_uses_waivers_end_to_end(tmp_path):
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion":3,"packages":{"":{},"node_modules/lodash":{"version":"4.17.0","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.0.tgz"}}}')
    post = lambda url, body: {"results": [{"vulns": [{"id": "GHSA-1"}]}]}
    get = lambda url: {"version": {"licences": ["MIT"]}}
    def vuln(waived):
        r = deps.project(str(tmp_path), [], post=post, get=get, waived=waived, today=TODAY, seen=set())
        return next(x for x in r if x.id.endswith(".vulns"))
    assert vuln(None).status == "warn"
    ok = vuln([w()])
    assert ok.status == "pass" and "waived: GHSA-1 in lodash until 2027-01-01 by anna" in ok.evidence
    assert vuln([w(expires=date(2026, 1, 1))]).status == "warn"       # expired: the finding is back
    assert vuln([w(owner="")]).status == "warn"                       # no owner: not honoured


def test_obligations_report_groups_by_year_and_keeps_unscheduled_and_events():
    from judged import obligations
    cat = [{"id": "a", "kind": "periodic", "cadence_days": 365, "framework": "F", "title": "Annual A", "verify": "v", "region": ["UK"]},
           {"id": "b", "kind": "periodic", "cadence_days": 30, "framework": "F", "title": "Monthly B", "verify": "v", "region": ["UK"]},
           {"id": "c", "kind": "periodic", "cadence_days": 90, "framework": "F", "title": "No date C", "verify": "v", "region": ["UK"]},
           {"id": "d", "kind": "event", "deadline": "72 hours", "framework": "G", "title": "Breach D", "verify": "v", "region": ["UK"]}]
    cfg = {"company": {"regions": ["UK"]}, "obligation": [{"id": "a", "last_done": date(2026, 6, 1)}, {"id": "b", "last_done": date(2026, 9, 1)}]}
    orig = obligations.for_regions
    obligations.for_regions = lambda regions, cat_=None: cat
    try:
        text = obligations.report(cfg, TODAY)
    finally:
        obligations.for_regions = orig
    order = [text.index(s) for s in ("Overdue", "\n2027", "No date yet", "Event-driven")]
    assert order == sorted(order) and "Monthly B" in text and "(54 days late)" in text
    assert text.index("Monthly B") < text.index("2027") < text.index("Annual A")       # overdue first, then by year
    assert "No date C" in text[text.index("No date yet"):] and "deadline: 72 hours" in text


def test_obligations_report_names_unknown_ids_instead_of_ignoring_them():
    from judged import obligations
    text = obligations.report({"company": {"regions": ["UK"]}, "obligation": [{"id": "cyber-essentials-renewal", "last_done": date(2026, 3, 1)}]}, TODAY)
    assert "Unknown obligation id" in text and "cyber-essentials-renewal" in text and "ce-cert" in text
    assert "Unknown" not in obligations.report({"company": {"regions": ["UK"]}, "obligation": [{"id": "ce-cert", "last_done": date(2026, 3, 1)}]}, TODAY)
